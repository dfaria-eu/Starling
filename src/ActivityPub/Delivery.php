<?php
declare(strict_types=1);

namespace App\ActivityPub;

use App\Models\{DB, CryptoModel, RemoteActorModel, StatusModel};

class Delivery
{
    /** @var int[] */
    private const RETRY_DELAYS = [300, 900, 3600, 14400, 43200, 86400, 172800]; // 5m, 15m, 1h, 4h, 12h, 24h, 48h
    private const PROCESSING_LEASE_SECONDS = 120;
    private const ATTEMPT_LOG_RETENTION_DAYS = 14;
    private const ATTEMPT_LOG_MAX_ROWS = 5000;
    public const INTERNAL_WAKE_BATCH = 15;
    public const REQUEST_DRAIN_BATCH = 3;
    public const INBOX_DRAIN_BATCH = 5;
    private const WAKE_FALLBACK_BATCH = 10;
    private const WAKE_FALLBACK_MAX_CYCLES = 2;

    private static function closeCurlHandle($ch): void
    {
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
    }

    private static function logQueue(string $event, array $context = [], string $throttleKey = '', int $windowSeconds = 60): void
    {
        try {
            if ($throttleKey !== '' && !throttle_allow('delivery_queue_log:' . $throttleKey, 1, $windowSeconds)) {
                return;
            }
            $parts = [];
            foreach ($context as $key => $value) {
                if ($value === '' || $value === null) continue;
                if (is_bool($value)) {
                    $value = $value ? 'true' : 'false';
                } elseif (is_float($value)) {
                    $value = number_format($value, 3, '.', '');
                } elseif (is_array($value)) {
                    $value = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                }
                $parts[] = $key . '=' . $value;
            }
            error_log('[Starling][delivery_queue] ' . $event . ($parts ? ' ' . implode(' ', $parts) : ''));
        } catch (\Throwable) {
        }
    }

    private static function drainWakeFallback(): void
    {
        $cycles = 0;
        do {
            self::processRetryQueue(self::WAKE_FALLBACK_BATCH);
            $cycles++;
        } while ($cycles < self::WAKE_FALLBACK_MAX_CYCLES && self::hasDueRetries());
    }

    private static function isQueueableUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!$parts || strtolower((string)($parts['scheme'] ?? '')) !== 'https') return false;
        if (empty($parts['host']) || !empty($parts['user']) || !empty($parts['pass'])) return false;
        $hostPart = explode('/', preg_replace('#^https?://#', '', $url))[0] ?? '';
        if (str_contains($hostPart, '@')) return false;
        return true;
    }

    private static function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }
        if (in_array($ip, ['127.0.0.1', '0.0.0.0', '::1'], true) || str_starts_with($ip, '169.254.')) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $bin = inet_pton($ip);
            if ($bin === false) return false;
            $b0 = ord($bin[0]);
            $b1 = ord($bin[1]);
            if (($b0 === 0xfe) && (($b1 & 0xc0) === 0x80)) return false;
            if (($b0 & 0xfe) === 0xfc) return false;
        }
        return true;
    }

    /**
     * Distinguish malformed/unsafe URLs from transient DNS failures.
     *
     * @return array{state:'ok'|'retry'|'terminal', error:string}
     */
    private static function classifyInboxUrl(string $url): array
    {
        if (!self::isQueueableUrl($url)) {
            return ['state' => 'terminal', 'error' => 'malformed_url'];
        }

        $host = (string)(parse_url($url, PHP_URL_HOST) ?? '');
        if ($host === '') {
            return ['state' => 'terminal', 'error' => 'malformed_url'];
        }

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return self::isPublicIp($host)
                ? ['state' => 'ok', 'error' => '']
                : ['state' => 'terminal', 'error' => 'unsafe_url'];
        }

        if (RemoteActorModel::isSafeUrl($url)) {
            return ['state' => 'ok', 'error' => ''];
        }

        $resolution = RemoteActorModel::resolveHostIpsDetailed($host);
        $resolved = array_values(array_unique($resolution['ips'] ?? []));
        if (!$resolved) {
            return match ($resolution['status'] ?? 'dns_unresolved') {
                'dns_nxdomain' => ['state' => 'terminal', 'error' => 'network: dns_nxdomain'],
                'dns_tempfail' => ['state' => 'retry', 'error' => 'network: dns_tempfail'],
                default => ['state' => 'retry', 'error' => 'network: dns_unresolved'],
            };
        }
        foreach ($resolved as $ip) {
            if (!self::isPublicIp($ip)) {
                return ['state' => 'terminal', 'error' => 'unsafe_url'];
            }
        }

        return ['state' => 'retry', 'error' => 'network: safe_url_check_failed'];
    }

    private static function payloadHash(string $actorId, string $inboxUrl, string $payload): string
    {
        return hash('sha256', $actorId . "\n" . $inboxUrl . "\n" . $payload);
    }

    private static function summarizeResponseBody(string $body): string
    {
        $body = trim($body);
        if ($body === '') return '';
        $body = preg_replace('/\s+/u', ' ', $body) ?? $body;
        return mb_substr($body, 0, 300);
    }

    private static function summarizeErrorDetail(string $detail): string
    {
        $detail = trim($detail);
        if ($detail === '') return '';
        $detail = preg_replace('/\s+/u', ' ', $detail) ?? $detail;
        return mb_substr($detail, 0, 180);
    }

    private static function retryDelayForAttempt(int $attempts, int $httpCode = 0, array $responseHeaders = [], string $bucket = ''): int
    {
        $delay = self::RETRY_DELAYS[max(0, $attempts - 1)] ?? 86400;
        if ($httpCode === 429 || $bucket === 'rate_limited') {
            $retryAfter = (int)($responseHeaders['retry-after'] ?? 0);
            if ($retryAfter > 0) {
                return max($delay, min($retryAfter, 172800));
            }
            return max($delay, 1800);
        }
        if ($bucket === 'dns_tempfail') return min($delay, 900);
        if ($bucket === 'network') return min($delay, 1800);
        return $delay;
    }

    private static function payloadMeta(array $activity): array
    {
        $type = (string)($activity['type'] ?? 'Unknown');
        $object = $activity['object'] ?? null;
        $objectType = '';
        $objectRef = '';
        if (is_array($object)) {
            $objectType = (string)($object['type'] ?? '');
            $objectRef = (string)($object['id'] ?? $object['url'] ?? $object['uri'] ?? '');
        } elseif (is_string($object)) {
            $objectType = 'ref';
            $objectRef = $object;
        }
        return ['activity_type' => $type, 'object_type' => $objectType, 'object_ref' => $objectRef];
    }

    private static function ensureAttemptLogTable(): void
    {
        static $done = false;
        if ($done) return;
        DB::pdo()->exec("CREATE TABLE IF NOT EXISTS delivery_attempt_log (
            id TEXT PRIMARY KEY,
            queue_id TEXT NOT NULL DEFAULT '',
            actor_id TEXT NOT NULL,
            inbox_url TEXT NOT NULL,
            domain TEXT NOT NULL DEFAULT '',
            activity_type TEXT NOT NULL DEFAULT '',
            object_type TEXT NOT NULL DEFAULT '',
            object_ref TEXT NOT NULL DEFAULT '',
            attempt_no INTEGER NOT NULL DEFAULT 0,
            http_code INTEGER NOT NULL DEFAULT 0,
            outcome TEXT NOT NULL DEFAULT '',
            error_bucket TEXT NOT NULL DEFAULT '',
            error_detail TEXT NOT NULL DEFAULT '',
            response_body TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )");
        DB::pdo()->exec("CREATE INDEX IF NOT EXISTS idx_delivery_attempt_log_created ON delivery_attempt_log(created_at DESC)");
        DB::pdo()->exec("CREATE INDEX IF NOT EXISTS idx_delivery_attempt_log_domain ON delivery_attempt_log(domain, created_at DESC)");
        DB::pdo()->exec("CREATE INDEX IF NOT EXISTS idx_delivery_attempt_log_bucket ON delivery_attempt_log(error_bucket, created_at DESC)");
        self::pruneAttemptLog();
        $done = true;
    }

    private static function pruneAttemptLog(): void
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - (self::ATTEMPT_LOG_RETENTION_DAYS * 86400));
        DB::run('DELETE FROM delivery_attempt_log WHERE created_at < ?', [$before]);
        $count = (int)(DB::one('SELECT COUNT(*) c FROM delivery_attempt_log')['c'] ?? 0);
        if ($count > self::ATTEMPT_LOG_MAX_ROWS) {
            $drop = $count - self::ATTEMPT_LOG_MAX_ROWS;
            DB::run(
                "DELETE FROM delivery_attempt_log
                  WHERE id IN (
                    SELECT id FROM delivery_attempt_log
                    ORDER BY created_at ASC
                    LIMIT ?
                  )",
                [$drop]
            );
        }
    }

    private static function recordAttemptLog(array $row, array $activity, int $attemptNo, int $code, string $outcome, string $bucket, string $detail = '', string $responseBody = ''): void
    {
        try {
            self::ensureAttemptLogTable();
            $meta = self::payloadMeta($activity);
            DB::insertIgnore('delivery_attempt_log', [
                'id' => uuid(),
                'queue_id' => (string)($row['id'] ?? ''),
                'actor_id' => (string)($row['actor_id'] ?? ''),
                'inbox_url' => (string)($row['inbox_url'] ?? ''),
                'domain' => (string)(parse_url((string)($row['inbox_url'] ?? ''), PHP_URL_HOST) ?? ''),
                'activity_type' => $meta['activity_type'],
                'object_type' => $meta['object_type'],
                'object_ref' => mb_substr($meta['object_ref'], 0, 255),
                'attempt_no' => $attemptNo,
                'http_code' => $code,
                'outcome' => $outcome,
                'error_bucket' => $bucket,
                'error_detail' => self::summarizeErrorDetail($detail),
                'response_body' => self::summarizeResponseBody($responseBody),
                'created_at' => now_iso(),
            ]);
            self::pruneAttemptLog();
        } catch (\Throwable) {
        }
    }

    /**
     * @param array<string,string> $responseHeaders
     * @return array{bucket:string,detail:string,terminal:bool}
     */
    private static function classifyDeliveryFailure(int $code, string $lastError, string $responseBody = '', array $responseHeaders = []): array
    {
        $detail = $lastError !== '' ? $lastError : ($code > 0 ? 'http_' . $code : 'unknown');
        $body = strtolower($responseBody);
        $err = strtolower($lastError);

        if (str_starts_with($lastError, 'network: dns_tempfail')) {
            return ['bucket' => 'dns_tempfail', 'detail' => $detail, 'terminal' => false];
        }
        if (str_starts_with($lastError, 'network: dns_nxdomain')) {
            return ['bucket' => 'dns_nxdomain', 'detail' => $detail, 'terminal' => true];
        }
        if (str_starts_with($lastError, 'network: dns_unresolved')) {
            return ['bucket' => 'dns_unresolved', 'detail' => $detail, 'terminal' => false];
        }
        if (str_starts_with($lastError, 'network: safe_url_check_failed')) {
            return ['bucket' => 'network', 'detail' => $detail, 'terminal' => false];
        }
        if (str_starts_with($lastError, 'unsafe_url') || str_starts_with($lastError, 'malformed_url')) {
            return ['bucket' => 'unsafe_url', 'detail' => $detail, 'terminal' => true];
        }
        if (str_starts_with($lastError, 'network:')) {
            return ['bucket' => 'network', 'detail' => $detail, 'terminal' => false];
        }
        if ($code === 429) {
            $retryAfter = trim((string)($responseHeaders['retry-after'] ?? ''));
            $detail = $retryAfter !== '' ? ($detail . ' retry-after=' . $retryAfter) : $detail;
            return ['bucket' => 'rate_limited', 'detail' => $detail, 'terminal' => false];
        }
        if ($code === 401) {
            $bucket = str_contains($body, 'verification failed') ? 'auth_signature' : 'http_401';
            return ['bucket' => $bucket, 'detail' => $detail, 'terminal' => false];
        }
        if ($code === 403) {
            return ['bucket' => 'http_403', 'detail' => $detail, 'terminal' => true];
        }
        if (in_array($code, [404, 405, 410, 422], true)) {
            return ['bucket' => 'http_' . $code, 'detail' => $detail, 'terminal' => true];
        }
        if ($code === 400) {
            return ['bucket' => 'http_400', 'detail' => $detail, 'terminal' => true];
        }
        if ($code >= 500 && $code <= 599) {
            return ['bucket' => 'remote_5xx', 'detail' => $detail, 'terminal' => false];
        }
        if ($code >= 400 && $code <= 499) {
            return ['bucket' => 'http_4xx', 'detail' => $detail, 'terminal' => false];
        }

        return ['bucket' => 'unknown', 'detail' => $detail ?: $err, 'terminal' => false];
    }

    private static function wakeSecretPath(): string
    {
        return ROOT . '/storage/runtime/queue_wake.key';
    }

    public static function wakeSecret(): string
    {
        $path = self::wakeSecretPath();
        $dir  = dirname($path);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        if (!is_file($path)) {
            @file_put_contents($path, bin2hex(random_bytes(32)), LOCK_EX);
            @chmod($path, 0600);
        }
        return trim((string)@file_get_contents($path));
    }

    public static function hasDueRetries(): bool
    {
        try {
            self::ensureQueueTable();
            self::pruneFailedQueueRows();
            $now = gmdate('Y-m-d\TH:i:s\Z');
            return (bool)DB::one(
                "SELECT 1
                   FROM delivery_queue
                  WHERE next_retry_at <= ?
                    AND attempts <= 7
                    AND (processing_until='' OR processing_until<=?)
                  LIMIT 1",
                [$now, $now]
            );
        } catch (\Throwable) {
            return false;
        }
    }

    public static function nudgeQueue(bool $force = false): void
    {
        // The PHP built-in server is single-threaded. Self-HTTP wakeups deadlock there
        // and make write requests hang during local smoke tests.
        if (PHP_SAPI === 'cli-server') return;

        if (!$force && !throttle_allow('delivery_queue_wake_http', 5)) return;

        $ch = curl_init(AP_BASE_URL . '/internal/queue-wake');
        curl_setopt_array($ch, [
            CURLOPT_POST               => true,
            CURLOPT_POSTFIELDS         => '',
            CURLOPT_RETURNTRANSFER     => false,
            CURLOPT_HEADER             => false,
            CURLOPT_NOSIGNAL           => true,
            CURLOPT_CONNECTTIMEOUT_MS  => 300,
            CURLOPT_TIMEOUT_MS         => 800,
            CURLOPT_SSL_VERIFYPEER     => true,
            CURLOPT_SSL_VERIFYHOST     => 2,
            CURLOPT_HTTPHEADER         => [
                'X-Queue-Wake: ' . self::wakeSecret(),
                'Connection: close',
                'Content-Length: 0',
            ],
        ]);
        $ok = @curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        self::closeCurlHandle($ch);

        // Shared hosts sometimes block loopback/self-HTTP intermittently. In that case,
        // fall back to draining a small local slice after the response instead of leaving
        // the queue stuck until the next incoming request.
        if ($ok === false || $code >= 400 || $code === 0) {
            self::logQueue('wake_fallback', [
                'http_code' => $code,
                'curl_ok' => $ok !== false,
                'mode' => 'local_drain',
            ], 'wake_fallback', 30);
            self::drainWakeFallback();
        }
    }

    /** Send a signed activity to a single inbox URL. */
    public static function post(array $actor, string $inboxUrl, array $activity): bool
    {
        // SSRF protection: validate the inbox URL before connecting.
        if (!RemoteActorModel::isSafeUrl($inboxUrl)) return false;

        $body  = json_encode($activity, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $keyId = actor_url($actor['username']) . '#main-key';
        $hdrs  = CryptoModel::signRequest('POST', $inboxUrl, $actor['private_key'], $keyId, $body);

        $headerLines = [
            'Accept: application/activity+json, application/ld+json',
            'User-Agent: ' . AP_SOFTWARE . '/' . AP_VERSION . ' (+https://' . AP_DOMAIN . ')',
        ];
        foreach ($hdrs as $k => $v) $headerLines[] = "$k: $v";

        $ch = curl_init($inboxUrl);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => $headerLines,
        ]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        self::closeCurlHandle($ch);

        return $code >= 200 && $code < 300;
    }

    /**
     * Broadcast an activity to all followers of $actor.
     * Uses shared inboxes where possible (dedup by domain).
     * Failed deliveries are stored in delivery_queue for automatic retry.
     */
    public static function toFollowers(array $actor, array $activity): void
    {
        // Remote followers grouped by shared inbox
        $rows = DB::all(
            "SELECT ra.inbox_url, ra.shared_inbox, ra.domain
             FROM follows f
             JOIN remote_actors ra ON ra.id = f.follower_id
             WHERE f.following_id=? AND f.pending=0",
            [$actor['id']]
        );

        $blockedDomains = StatusModel::blockedDomains();

        $sent = [];
        foreach ($rows as $r) {
            // Skip delivery to server-wide blocked domains
            if ($blockedDomains && in_array($r['domain'], $blockedDomains, true)) continue;
            $inbox = $r['shared_inbox'] ?: $r['inbox_url'];
            if ($inbox && !in_array($inbox, $sent)) {
                $ok = self::post($actor, $inbox, $activity);
                if (!$ok) {
                    self::enqueueRetry($actor['id'], $inbox, $activity);
                }
                $sent[] = $inbox;
            }
        }
    }

    /**
     * Queue an activity for delivery to a single inbox.
     * With attempts=0 and next_retry_at=now(), processRetryQueue() picks it up
     * on the next incoming request — works on any hosting (no SAPI requirements).
     */
    public static function enqueue(array $actor, string $inboxUrl, array $activity): void
    {
        if (!self::isQueueableUrl($inboxUrl)) return;
        try {
            self::ensureQueueTable();
            $payload = json_encode($activity, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $hash    = self::payloadHash($actor['id'], $inboxUrl, $payload);
            $now     = gmdate('Y-m-d\TH:i:s\Z');
            $existing = DB::one(
                'SELECT id, next_retry_at, attempts FROM delivery_queue WHERE actor_id=? AND inbox_url=? AND payload_hash=? LIMIT 1',
                [$actor['id'], $inboxUrl, $hash]
            );
            if ($existing) {
                // Same delivery already queued: bring it forward instead of duplicating work.
                DB::update('delivery_queue', [
                    'attempts'        => 0,
                    'next_retry_at'   => $now,
                    'last_error'      => '',
                    'last_error_bucket' => '',
                    'last_error_detail' => '',
                    'last_http_code'  => 0,
                    'last_attempt_at' => '',
                    'last_response_body' => '',
                    'processing_until'=> '',
                ], 'id=?', [$existing['id']]);
            } else {
            DB::insertIgnore('delivery_queue', [
                'id'            => uuid(),
                'actor_id'      => $actor['id'],
                'inbox_url'     => $inboxUrl,
                'payload'       => $payload,
                'payload_hash'  => $hash,
                'attempts'      => 0,
                'next_retry_at' => $now, // process ASAP
                'created_at'    => now_iso(),
                'last_http_code'=> 0,
                'last_error'    => '',
                'last_error_bucket' => '',
                'last_error_detail' => '',
                'last_attempt_at' => '',
                'last_response_body' => '',
                'processing_until' => '',
            ]);
            }
            static $wakeScheduled = false;
            $requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
            if (!$wakeScheduled && $requestPath !== '/internal/queue-wake') {
                $wakeScheduled = true;
                defer_after_response(static function (): void {
                    self::nudgeQueue();
                });
            }
        } catch (\Throwable $e) {
            self::logQueue('enqueue_exception', [
                'inbox' => parse_url($inboxUrl, PHP_URL_HOST) ?? $inboxUrl,
                'error' => mb_substr($e->getMessage(), 0, 180),
            ], 'enqueue_exception', 60);
        }
    }

    /**
     * Queue an activity to all followers of $actor (shared-inbox dedup).
     * Returns immediately — delivery happens via processRetryQueue() on next request.
     */
    public static function queueToFollowers(array $actor, array $activity): void
    {
        $rows = DB::all(
            "SELECT ra.inbox_url, ra.shared_inbox, ra.domain
             FROM follows f
             JOIN remote_actors ra ON ra.id = f.follower_id
             WHERE f.following_id=? AND f.pending=0",
            [$actor['id']]
        );
        $blockedDomains = StatusModel::blockedDomains();
        $sent = [];
        foreach ($rows as $r) {
            if ($blockedDomains && in_array($r['domain'], $blockedDomains, true)) continue;
            $inbox = $r['shared_inbox'] ?: $r['inbox_url'];
            if ($inbox && !in_array($inbox, $sent)) {
                self::enqueue($actor, $inbox, $activity);
                $sent[] = $inbox;
            }
        }
    }

    /**
     * Queue an activity to a single remote actor's inbox.
     * Returns immediately — delivery happens via processRetryQueue() on next request.
     */
    public static function queueToActor(array $sender, array $remoteActor, array $activity): void
    {
        $inbox = $remoteActor['shared_inbox'] ?: $remoteActor['inbox_url'];
        if ($inbox) self::enqueue($sender, $inbox, $activity);
    }

    /**
     * Store a failed delivery in the retry queue.
     * Uses INSERT OR IGNORE so duplicate entries are not created.
     */
    private static function enqueueRetry(string $actorId, string $inboxUrl, array $activity): void
    {
        try {
            self::ensureQueueTable();
            $payload = json_encode($activity, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $hash    = self::payloadHash($actorId, $inboxUrl, $payload);
            $existing = DB::one(
                'SELECT id FROM delivery_queue WHERE actor_id=? AND inbox_url=? AND payload_hash=? LIMIT 1',
                [$actorId, $inboxUrl, $hash]
            );
            if ($existing) return;
            DB::insertIgnore('delivery_queue', [
                'id'            => uuid(),
                'actor_id'      => $actorId,
                'inbox_url'     => $inboxUrl,
                'payload'       => $payload,
                'payload_hash'  => $hash,
                'attempts'      => 1,
                'next_retry_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 300), // retry in 5 min
                'created_at'    => now_iso(),
                'last_http_code' => 0,
                'last_error' => '',
                'last_error_bucket' => '',
                'last_error_detail' => '',
                'last_attempt_at' => '',
                'last_response_body' => '',
                'processing_until' => '',
            ]);
        } catch (\Throwable) {
            // Retry storage failure is non-fatal — activity was already attempted once
        }
    }

    /**
     * @param array<string,string> $responseHeaders
     */
    private static function markFailedRow(array $row, int $code, string $lastError, string $responseBody = '', bool $terminal = false, array $responseHeaders = [], ?array $activity = null): void
    {
        $attempts = (int)$row['attempts'] + 1;
        $lastAttemptAt = now_iso();
        $responseBody = self::summarizeResponseBody($responseBody);
        $failure = self::classifyDeliveryFailure($code, $lastError, $responseBody, $responseHeaders);
        $bucket = $failure['bucket'];
        $detail = $failure['detail'];
        $terminal = $terminal || $failure['terminal'];

        if ($activity !== null) {
            self::recordAttemptLog($row, $activity, $attempts, $code, $terminal ? 'failed_terminal' : 'failed_retry', $bucket, $detail, $responseBody);
        }

        if ($terminal || $attempts > count(self::RETRY_DELAYS)) {
            DB::update('delivery_queue', [
                'attempts'        => 8,
                'next_retry_at'   => $lastAttemptAt,
                'last_http_code'  => $code,
                'last_error'      => $lastError,
                'last_error_bucket' => $bucket,
                'last_error_detail' => self::summarizeErrorDetail($detail),
                'last_attempt_at' => $lastAttemptAt,
                'last_response_body' => $responseBody,
                'processing_until'=> '',
            ], 'id=?', [$row['id']]);
            return;
        }

        $delay = self::retryDelayForAttempt($attempts, $code, $responseHeaders, $bucket);
        DB::update('delivery_queue', [
            'attempts'        => $attempts,
            'next_retry_at'   => gmdate('Y-m-d\TH:i:s\Z', time() + $delay),
            'last_http_code'  => $code,
            'last_error'      => $lastError,
            'last_error_bucket' => $bucket,
            'last_error_detail' => self::summarizeErrorDetail($detail),
            'last_attempt_at' => $lastAttemptAt,
            'last_response_body' => $responseBody,
            'processing_until'=> '',
        ], 'id=?', [$row['id']]);
    }

    /**
     * Process up to $limit pending deliveries from the queue in parallel (curl_multi).
     * All handles fire simultaneously — total wait time ≈ slowest server, not sum of all.
     * Called on each incoming inbox request; no cron required.
     */
    public static function processRetryQueue(int $limit = 20): void
    {
        $startedAt = microtime(true);
        $leased = 0;
        $successes = 0;
        $retryFailures = 0;
        $terminalFailures = 0;
        $skipped = 0;
        try {
            self::ensureQueueTable();
            self::pruneFailedQueueRows();
            $now  = gmdate('Y-m-d\TH:i:s\Z');
            $leaseUntil = gmdate('Y-m-d\TH:i:s\Z', time() + self::PROCESSING_LEASE_SECONDS);
            $candidates = DB::all(
                "SELECT * FROM delivery_queue
                  WHERE next_retry_at <= ?
                    AND attempts <= 7
                    AND (processing_until='' OR processing_until<=?)
                  ORDER BY next_retry_at ASC
                  LIMIT ?",
                [$now, $now, max($limit * 3, $limit)]
            );
            if (!$candidates) return;

            $rows = [];
            foreach ($candidates as $candidate) {
                $st = DB::run(
                    "UPDATE delivery_queue
                        SET processing_until=?
                      WHERE id=?
                        AND attempts<=7
                        AND (processing_until='' OR processing_until<=?)",
                    [$leaseUntil, $candidate['id'], $now]
                );
                if ($st->rowCount() < 1) {
                    continue;
                }
                $candidate['processing_until'] = $leaseUntil;
                $rows[] = $candidate;
                if (count($rows) >= $limit) {
                    break;
                }
            }
            if (!$rows) return;
            $leased = count($rows);

            // Build one signed cURL handle per row; skip rows with invalid actor/payload.
            $mh      = curl_multi_init();
            $handles = []; // keyed by row id: ['ch' => resource, 'row' => array]
            $responseHeadersMap = [];

            // Batch-fetch all actors needed for this batch (avoids N+1 queries).
            $actorIds = array_values(array_unique(array_column($rows, 'actor_id')));
            $ph       = implode(',', array_fill(0, count($actorIds), '?'));
            $actorsById = [];
            foreach (DB::all("SELECT * FROM users WHERE id IN ($ph)", $actorIds) as $a) {
                $actorsById[$a['id']] = $a;
            }

            foreach ($rows as $row) {
                $actor = $actorsById[$row['actor_id']] ?? null;
                if (!$actor) { DB::delete('delivery_queue', 'id=?', [$row['id']]); $skipped++; continue; }

                $activity = json_decode($row['payload'], true);
                if (!$activity) { DB::delete('delivery_queue', 'id=?', [$row['id']]); $skipped++; continue; }

                $urlState = self::classifyInboxUrl($row['inbox_url']);
                if ($urlState['state'] === 'terminal') {
                    self::markFailedRow($row, 0, $urlState['error'], '', true, [], $activity);
                    $terminalFailures++;
                    continue;
                }
                if ($urlState['state'] === 'retry') {
                    self::markFailedRow($row, 0, $urlState['error'], '', false, [], $activity);
                    $retryFailures++;
                    continue;
                }

                $body  = json_encode($activity, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $keyId = actor_url($actor['username']) . '#main-key';
                $hdrs  = CryptoModel::signRequest('POST', $row['inbox_url'], $actor['private_key'], $keyId, $body);

                $headerLines = [
                    'Accept: application/activity+json, application/ld+json',
                    'User-Agent: ' . AP_SOFTWARE . '/' . AP_VERSION . ' (+https://' . AP_DOMAIN . ')',
                ];
                foreach ($hdrs as $k => $v) $headerLines[] = "$k: $v";

                $ch = curl_init($row['inbox_url']);
                $rowId = (string)$row['id'];
                $responseHeadersMap[$rowId] = [];
                curl_setopt_array($ch, [
                    CURLOPT_POST           => true,
                    CURLOPT_POSTFIELDS     => $body,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_CONNECTTIMEOUT => 5,
                    CURLOPT_TIMEOUT        => 10,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_HTTPHEADER     => $headerLines,
                    CURLOPT_HEADERFUNCTION => static function ($ch, string $headerLine) use (&$responseHeadersMap, $rowId): int {
                        $trimmed = trim($headerLine);
                        if ($trimmed === '' || !str_contains($trimmed, ':')) {
                            return strlen($headerLine);
                        }
                        [$name, $value] = explode(':', $trimmed, 2);
                        $responseHeadersMap[$rowId][strtolower(trim($name))] = trim($value);
                        return strlen($headerLine);
                    },
                ]);

                curl_multi_add_handle($mh, $ch);
                $handles[$rowId] = ['ch' => $ch, 'row' => $row, 'activity' => $activity];
            }

            // Execute all handles in parallel.
            $active = 0;
            do {
                $status = curl_multi_exec($mh, $active);
                if ($active) curl_multi_select($mh, 1.0);
            } while ($active > 0 && $status === CURLM_OK);

            // Process results.
            foreach ($handles as $rowId => $handleInfo) {
                $ch = $handleInfo['ch'];
                $row = $handleInfo['row'];
                $activity = $handleInfo['activity'];
                $responseHeaders = $responseHeadersMap[$rowId] ?? [];
                $code     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlErr  = trim((string)curl_error($ch));
                $rawBody  = (string)curl_multi_getcontent($ch);
                $ok       = $code >= 200 && $code < 300;
                curl_multi_remove_handle($mh, $ch);
                self::closeCurlHandle($ch);

                if ($ok) {
                    self::recordAttemptLog($row, $activity, (int)$row['attempts'] + 1, $code, 'success', 'success', '', $rawBody);
                    DB::delete('delivery_queue', 'id=?', [$row['id']]);
                    $successes++;
                } else {
                    $lastError = $curlErr !== ''
                        ? ('network: ' . mb_substr($curlErr, 0, 180))
                        : ($code > 0 ? ('http_' . $code) : 'network: unknown');
                    $failure = self::classifyDeliveryFailure($code, $lastError, $rawBody, is_array($responseHeaders) ? $responseHeaders : []);
                    if ($failure['terminal']) {
                        $terminalFailures++;
                    } else {
                        $retryFailures++;
                    }
                    self::markFailedRow($row, $code, $lastError, $rawBody, false, is_array($responseHeaders) ? $responseHeaders : [], $activity);
                }
            }

            curl_multi_close($mh);
        } catch (\Throwable $e) {
            // Non-fatal — retry processing should never break inbox handling
            self::logQueue('process_exception', [
                'limit' => $limit,
                'leased' => $leased,
                'duration_s' => microtime(true) - $startedAt,
                'error' => mb_substr($e->getMessage(), 0, 180),
            ], 'process_exception', 30);
            return;
        }

        $duration = microtime(true) - $startedAt;
        $processed = $successes + $retryFailures + $terminalFailures + $skipped;
        if (
            $processed > 0 &&
            ($retryFailures > 0 || $terminalFailures > 0 || $duration >= 5.0)
        ) {
            self::logQueue('batch', [
                'limit' => $limit,
                'leased' => $leased,
                'processed' => $processed,
                'success' => $successes,
                'retry' => $retryFailures,
                'terminal' => $terminalFailures,
                'skipped' => $skipped,
                'due_remaining' => self::hasDueRetries(),
                'duration_s' => $duration,
            ], 'batch_summary', 20);
        }
    }

    private static function ensureQueueTable(): void
    {
        static $created = false;
        if ($created) return;
        DB::pdo()->exec("CREATE TABLE IF NOT EXISTS delivery_queue (
            id            TEXT PRIMARY KEY,
            actor_id      TEXT NOT NULL,
            inbox_url     TEXT NOT NULL,
            payload       TEXT NOT NULL,
            payload_hash  TEXT NOT NULL DEFAULT '',
            attempts      INTEGER NOT NULL DEFAULT 1,
            next_retry_at TEXT NOT NULL,
            created_at    TEXT NOT NULL,
            last_http_code INTEGER NOT NULL DEFAULT 0,
            last_error    TEXT NOT NULL DEFAULT '',
            last_error_bucket TEXT NOT NULL DEFAULT '',
            last_error_detail TEXT NOT NULL DEFAULT '',
            last_attempt_at TEXT NOT NULL DEFAULT '',
            last_response_body TEXT NOT NULL DEFAULT '',
            processing_until TEXT NOT NULL DEFAULT ''
        )");
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN payload_hash TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN last_http_code INTEGER NOT NULL DEFAULT 0"); } catch (\Throwable) {}
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN last_error TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN last_error_bucket TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN last_error_detail TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN last_response_body TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { DB::pdo()->exec("ALTER TABLE delivery_queue ADD COLUMN processing_until TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        self::ensureAttemptLogTable();
        try {
            $rows = DB::all("SELECT id, actor_id, inbox_url, payload FROM delivery_queue WHERE payload_hash=''");
            foreach ($rows as $row) {
                DB::update(
                    'delivery_queue',
                    ['payload_hash' => self::payloadHash((string)$row['actor_id'], (string)$row['inbox_url'], (string)$row['payload'])],
                    'id=?',
                    [$row['id']]
                );
            }
        } catch (\Throwable) {}
        try {
            $dupes = DB::all(
                "SELECT actor_id, inbox_url, payload_hash, MIN(id) AS keep_id
                 FROM delivery_queue
                 WHERE payload_hash != ''
                 GROUP BY actor_id, inbox_url, payload_hash
                 HAVING COUNT(*) > 1"
            );
            foreach ($dupes as $dupe) {
                DB::delete(
                    'delivery_queue',
                    'actor_id=? AND inbox_url=? AND payload_hash=? AND id<>?',
                    [$dupe['actor_id'], $dupe['inbox_url'], $dupe['payload_hash'], $dupe['keep_id']]
                );
            }
        } catch (\Throwable) {}
        DB::pdo()->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_dq_dedupe ON delivery_queue(actor_id, inbox_url, payload_hash)");
        DB::pdo()->exec("CREATE INDEX IF NOT EXISTS idx_dq_ready ON delivery_queue(next_retry_at, processing_until, attempts)");
        $created = true;
    }

    private static function pruneFailedQueueRows(int $days = 7): void
    {
        static $done = false;
        if ($done) return;
        $done = true;
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - ($days * 86400));
        DB::run('DELETE FROM delivery_queue WHERE attempts >= 8 AND created_at < ?', [$before]);
    }

    /** Deliver to a specific remote actor's inbox. */
    public static function toActor(array $sender, array $remoteActor, array $activity): bool
    {
        $inbox = $remoteActor['shared_inbox'] ?: $remoteActor['inbox_url'];
        if (!$inbox) return false;
        return self::post($sender, $inbox, $activity);
    }

    /**
     * Queue a public activity to all accepted relay inboxes.
     * Only call for public/unlisted posts — relays must not receive private or direct content.
     */
    public static function queueToRelays(array $actor, array $activity): void
    {
        $relays = DB::all("SELECT inbox_url FROM relay_subscriptions WHERE status='accepted'");
        foreach ($relays as $r) {
            if ($r['inbox_url']) self::enqueue($actor, $r['inbox_url'], $activity);
        }
    }
}
