<?php
declare(strict_types=1);

namespace App\Models;

class RemoteActorModel
{
    private const DNS_CACHE_TTL_SECONDS = 600;

    private static function closeCurlHandle($ch): void
    {
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
    }

    /**
     * Fetch and cache a remote actor by AP URL.
     * Uses a signed GET if the actor's private key is available (required by some servers).
     */
    public static function fetch(string $url, bool $force = false): ?array
    {
        return self::fetchDetailed($url, $force)['actor'];
    }

    /**
     * Fetch and cache a remote actor by AP URL, with diagnostics.
     *
     * @return array{ok:bool,actor:?array,error:string}
     */
    public static function fetchDetailed(string $url, bool $force = false): array
    {
        // Rejeitar URLs malformadas ou com credenciais embutidas (user@host)
        if ($url === '' || !preg_match('#^https?://#i', $url)) {
            return ['ok' => false, 'actor' => null, 'error' => 'invalid_actor_url'];
        }
        $parsedHost = parse_url($url, PHP_URL_HOST) ?? '';
        if ($parsedHost && is_local($parsedHost)) {
            return ['ok' => false, 'actor' => null, 'error' => 'local_actor_url_rejected'];
        }
        if (str_contains($parsedHost, '@') || str_contains($parsedHost, ' ')) {
            return ['ok' => false, 'actor' => null, 'error' => 'invalid_actor_host'];
        }
        if (!empty(parse_url($url, PHP_URL_USER))) {
            return ['ok' => false, 'actor' => null, 'error' => 'embedded_credentials_rejected'];
        }

        if (!$force) {
            $cached = DB::one('SELECT * FROM remote_actors WHERE id=?', [$url]);
            if ($cached && $cached['fetched_at'] > gmdate('Y-m-d\TH:i:s\Z', time() - 3600)) {
                return ['ok' => true, 'actor' => $cached, 'error' => ''];
            }
        }

        // SSRF protection: reject private/loopback addresses
        if (!self::isSafeUrl($url)) {
            $dns = self::resolveHostIpsDetailed($parsedHost);
            $error = $dns['status'] !== 'ok'
                ? $dns['status']
                : 'unsafe_url';
            return ['ok' => false, 'actor' => null, 'error' => $error];
        }

        $http = self::httpGetDetailed($url, 'application/activity+json');
        if (!$http['ok']) {
            return ['ok' => false, 'actor' => null, 'error' => $http['error']];
        }
        $data = $http['data'];
        if (!$data || empty($data['id'])) {
            return ['ok' => false, 'actor' => null, 'error' => 'actor_response_missing_id'];
        }

        // fetchCounts=true on explicit profile refreshes (force=true); skip during inbox processing
        $actor = self::upsert($data, $force);
        return $actor
            ? ['ok' => true, 'actor' => $actor, 'error' => '']
            : ['ok' => false, 'actor' => null, 'error' => 'actor_upsert_failed'];
    }

    /** Resolve @user@domain via WebFinger, then fetch actor. */
    public static function fetchByAcct(string $username, string $domain): ?array
    {
        if (is_local($domain)) return null;

        // Check cache first (still valid if < 1h old)
        $cached = DB::one('SELECT * FROM remote_actors WHERE username=? AND domain=?', [$username, $domain]);
        if ($cached && $cached['fetched_at'] > gmdate('Y-m-d\TH:i:s\Z', time() - 3600)) {
            return $cached;
        }

        if (!self::isSafeUrl("https://$domain/")) return null; // reject unsafe (private/loopback) domains

        $wfUrl = "https://$domain/.well-known/webfinger?resource=acct:$username@$domain";
        $wf    = self::httpGet($wfUrl, 'application/jrd+json, application/json');
        if (!$wf) return $cached; // return stale cache if webfinger fails

        $actorUrl = null;
        foreach ($wf['links'] ?? [] as $link) {
            $rel  = $link['rel']  ?? '';
            $type = $link['type'] ?? '';
            if ($rel === 'self' && (str_contains($type, 'activity+json') || str_contains($type, 'ld+json'))) {
                $actorUrl = $link['href'] ?? null;
                break;
            }
        }
        if (!$actorUrl) return $cached;

        $result = self::fetch($actorUrl, true);
        return $result ?? $cached; // return stale if fresh fetch failed
    }

    private static function upsert(array $d, bool $fetchCounts = false): ?array
    {
        $parsed  = parse_url($d['id']);
        $domain  = $parsed['host'] ?? '';
        $now     = now_iso();

        $row = [
            'id'             => $d['id'],
            'masto_id'       => md5($d['id']),
            'username'       => $d['preferredUsername'] ?? '',
            'domain'         => $domain,
            'display_name'   => $d['name'] ?? ($d['preferredUsername'] ?? ''),
            'bio'            => $d['summary'] ?? '',
            'avatar'         => self::extractImage($d['icon']  ?? null),
            'header_img'     => self::extractImage($d['image'] ?? null),
            'public_key'     => self::extractPublicKey($d['publicKey'] ?? null),
            'url'            => self::extractProfileUrl($d['url'] ?? null, $d['id']),
            'inbox_url'      => $d['inbox'] ?? '',
            'shared_inbox'   => $d['endpoints']['sharedInbox'] ?? ($d['inbox'] ?? ''),
            'outbox_url'     => $d['outbox']    ?? '',
            'followers_url'  => $d['followers'] ?? '',
            'following_url'  => $d['following'] ?? '',
            'fields'         => self::extractFields($d['attachment'] ?? []),
            'also_known_as'  => json_encode((array)($d['alsoKnownAs'] ?? [])),
            'moved_to'       => is_string($d['movedTo'] ?? null) ? $d['movedTo'] : '',
            'is_locked'      => ($d['manuallyApprovesFollowers'] ?? false) ? 1 : 0,
            'is_bot'         => in_array($d['type'] ?? '', ['Service', 'Application']) ? 1 : 0,
            // Tentar obter contadores reais do actor AP.
            // fetchCounts=true only when explicitly refreshing a profile (force=true) —
            // avoids 3 extra HTTP requests on every inbox message.
            'follower_count' => self::collectionCount($d['followers'] ?? null, $fetchCounts),
            'following_count'=> self::collectionCount($d['following'] ?? null, $fetchCounts),
            'status_count'   => self::collectionCount($d['outbox'] ?? null, $fetchCounts),
            'published_at'   => $d['published'] ?? null,
            'raw_json'       => json_encode($d),
            'fetched_at'     => $now,
        ];

        $exists = DB::one('SELECT id, follower_count, following_count, status_count FROM remote_actors WHERE id=?', [$d['id']]);
        if ($exists) {
            $upd = $row; unset($upd['id']);
            // Preserve existing counts when not explicitly fetching them (inbox processing path)
            if (!$fetchCounts) {
                $upd['follower_count']  = (int)$exists['follower_count']  ?: $upd['follower_count'];
                $upd['following_count'] = (int)$exists['following_count'] ?: $upd['following_count'];
                $upd['status_count']    = (int)$exists['status_count']    ?: $upd['status_count'];
            }
            DB::update('remote_actors', $upd, 'id=?', [$d['id']]);
        } else {
            // New actor — fetch counts once on first insert so timeline/notifications
            // show correct numbers from the start, without waiting for a force refresh.
            $row['follower_count']  = self::collectionCount($d['followers'] ?? null, true);
            $row['following_count'] = self::collectionCount($d['following'] ?? null, true);
            $row['status_count']    = self::collectionCount($d['outbox']    ?? null, true);
            DB::insertIgnore('remote_actors', $row);
        }

        return DB::one('SELECT * FROM remote_actors WHERE id=?', [$d['id']]);
    }

    /**
     * Obtém o totalItems de uma collection AP.
     * - Se o valor for um objecto com totalItems (já embutido no JSON do actor), usa-o.
     * - Se for uma URL string e $doFetch=true, faz um GET ao root da collection
     *   (resposta leve: só o totalItems, sem items) para obter o count real.
     * - Com $doFetch=false (default, usado durante inbox processing) devolve 0
     *   para evitar pedidos HTTP extra em cada mensagem recebida.
     */
    private static function collectionCount(mixed $val, bool $doFetch = false): int
    {
        if (!$val) return 0;
        // Count already embedded in the actor JSON as an object
        if (is_array($val) && isset($val['totalItems'])) return (int)$val['totalItems'];
        // String URL — only fetch when explicitly refreshing a profile
        if (is_string($val) && $doFetch) {
            $data = self::httpGet($val, 'application/activity+json');
            if ($data && isset($data['totalItems'])) return (int)$data['totalItems'];
        }
        return 0;
    }

    private static function extractFields(mixed $attachment): string
    {
        if (!is_array($attachment)) return '[]';
        $fields = [];
        foreach ($attachment as $item) {
            if (!is_array($item) || ($item['type'] ?? '') !== 'PropertyValue') continue;
            $name = trim((string)($item['name'] ?? ''));
            if (!$name) continue;
            $fields[] = ['name' => $name, 'value' => $item['value'] ?? ''];
        }
        return json_encode(array_slice($fields, 0, 4));
    }

    private static function extractImage(mixed $icon): string
    {
        if (is_string($icon)) return $icon;
        if (!is_array($icon)) return '';
        $url = $icon['url'] ?? $icon['href'] ?? '';
        if (is_string($url)) return $url;
        if (is_array($url)) {
            foreach ($url as $candidate) {
                if (is_string($candidate) && $candidate !== '') return $candidate;
                if (is_array($candidate) && is_string($candidate['href'] ?? null)) return $candidate['href'];
                if (is_array($candidate) && is_string($candidate['url'] ?? null)) return $candidate['url'];
            }
        }
        return '';
    }

    private static function extractPublicKey(mixed $publicKey): string
    {
        foreach (self::candidateKeys($publicKey) as $candidate) {
            if (is_string($candidate['publicKeyPem'] ?? null)) {
                return $candidate['publicKeyPem'];
            }
            if (is_string($candidate['publicKeyMultibase'] ?? null)) {
                $pem = self::multibaseToPem($candidate['publicKeyMultibase']);
                if ($pem !== '') return $pem;
            }
        }
        return '';
    }

    private static function extractProfileUrl(mixed $url, string $fallback): string
    {
        if (is_string($url) && $url !== '') return $url;
        if (!is_array($url)) return $fallback;
        foreach ($url as $candidate) {
            if (is_string($candidate) && $candidate !== '') return $candidate;
            if (!is_array($candidate)) continue;
            $href = $candidate['href'] ?? $candidate['url'] ?? '';
            if (!is_string($href) || $href === '') continue;
            $mediaType = strtolower((string)($candidate['mediaType'] ?? $candidate['mimeType'] ?? ''));
            if ($mediaType === '' || str_contains($mediaType, 'text/html')) return $href;
        }
        return $fallback;
    }

    /**
     * HTTP GET with optional HTTP Signature for signed fetches.
     * Some servers (Misskey, Calckey, Sharkey) require signed GETs.
     */
    public static function httpGet(string $url, string $accept, ?array $signingActor = null): ?array
    {
        return self::httpGetDetailed($url, $accept, $signingActor)['data'];
    }

    /**
     * HTTP GET with diagnostics.
     *
     * @return array{ok:bool,data:?array,error:string,http_code:int}
     */
    public static function httpGetDetailed(string $url, string $accept, ?array $signingActor = null): array
    {
        if (!self::isSafeUrl($url)) {
            return ['ok' => false, 'data' => null, 'error' => 'unsafe_url', 'http_code' => 0];
        }

        $headerLines = [
            'Accept: ' . $accept,
            'User-Agent: ' . AP_SOFTWARE . '/' . AP_VERSION . ' (+https://' . AP_DOMAIN . ')',
        ];

        // Signed GET: use instance actor (first admin user) or provided actor
        if ($signingActor === null) {
            $signingActor = DB::one('SELECT * FROM users WHERE is_admin=1 AND is_suspended=0 ORDER BY created_at ASC LIMIT 1');
        }
        if ($signingActor && !empty($signingActor['private_key'])) {
            $keyId    = actor_url($signingActor['username']) . '#main-key';
            $signHdrs = \App\Models\CryptoModel::signRequest('GET', $url, $signingActor['private_key'], $keyId);
            foreach ($signHdrs as $k => $v) {
                if ($k !== 'Content-Type' && $k !== 'Digest') {
                    $headerLines[] = "$k: $v";
                }
            }
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => $headerLines,
        ]);
        $raw      = curl_exec($ch);
        $errno    = curl_errno($ch);
        $err      = curl_error($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        self::closeCurlHandle($ch);

        if ($raw === false) {
            return [
                'ok' => false,
                'data' => null,
                'error' => $errno === 6 ? 'dns_unresolved' : ('curl_error:' . ($err !== '' ? $err : (string)$errno)),
                'http_code' => $httpCode,
            ];
        }

        // SSRF protection: check redirect destination if the URL changed
        if ($finalUrl && $finalUrl !== $url && !self::isSafeUrl($finalUrl)) {
            return ['ok' => false, 'data' => null, 'error' => 'unsafe_redirect_url', 'http_code' => $httpCode];
        }

        if ($httpCode >= 400) {
            return ['ok' => false, 'data' => null, 'error' => 'http_' . $httpCode, 'http_code' => $httpCode];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return ['ok' => false, 'data' => null, 'error' => 'invalid_json_response', 'http_code' => $httpCode];
        }
        return ['ok' => true, 'data' => $data, 'error' => '', 'http_code' => $httpCode];
    }

    /**
     * SSRF protection: reject URLs pointing to private/loopback/link-local addresses.
     */
    public static function isSafeUrl(string $url): bool
    {
        $parsed = parse_url($url);
        $host   = $parsed['host'] ?? null;
        if (!$host) return false;

        // Rejeitar URLs com credenciais embutidas (user@host) — inválidas em AP
        if (!empty($parsed['user']) || !empty($parsed['pass'])) return false;

        // Rejeitar se a URL contém @ fora das credenciais (URL malformada)
        $urlWithoutScheme = preg_replace('#^https?://#', '', $url);
        if (str_contains(explode('/', $urlWithoutScheme)[0], '@')) return false;

        // Must be HTTPS in production (allow HTTP only in debug mode)
        $scheme = strtolower($parsed['scheme'] ?? '');
        if ($scheme !== 'https' && !AP_DEBUG) return false;

        $ips = self::resolveHostIps($host);
        if (!$ips) return false;
        foreach ($ips as $ip) {
            if (!self::isPublicIp($ip)) return false;
        }

        return true;
    }

    /**
     * Resolve A/AAAA records for a host, supporting IPv6-only instances.
     *
     * @return list<string>
     */
    public static function resolveHostIps(string $host): array
    {
        return self::resolveHostIpsDetailed($host)['ips'];
    }

    /**
     * Resolve A/AAAA records with classification and short cache.
     *
     * @return array{ips:list<string>,status:string,error:string,source:string}
     */
    public static function resolveHostIpsDetailed(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return ['ips' => [$host], 'status' => 'ok', 'error' => '', 'source' => 'literal_ip'];
        }

        $cached = self::dnsCacheGet($host);
        if ($cached !== null) {
            return $cached;
        }

        $ips = [];
        $status = 'unresolved';
        $error = '';
        $source = '';

        if (function_exists('dns_get_record')) {
            $dns = self::dnsGetRecordSafe($host);
            foreach ($dns['records'] as $rec) {
                if (!empty($rec['ip']) && filter_var($rec['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $ips[] = $rec['ip'];
                }
                if (!empty($rec['ipv6']) && filter_var($rec['ipv6'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $ips[] = $rec['ipv6'];
                }
            }
            if ($ips) {
                $status = 'ok';
                $source = 'dns_get_record';
            } elseif ($dns['error'] !== '') {
                $status = self::classifyDnsError($dns['error']);
                $error = $dns['error'];
            }
        }

        if (!$ips) {
            $ipv4 = gethostbyname($host);
            if (filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ips[] = $ipv4;
                $status = 'ok';
                $source = 'gethostbyname';
            }
        }

        if (!$ips) {
            $ips = self::resolveHostIpsViaDoh($host);
            if ($ips) {
                $status = 'ok';
                $source = 'doh';
            }
        }

        $result = [
            'ips' => array_values(array_unique($ips)),
            'status' => $ips ? 'ok' : $status,
            'error' => $ips ? '' : $error,
            'source' => $source,
        ];
        self::dnsCachePut($host, $result);
        return $result;
    }

    /**
     * Some shared/sandboxed PHP runtimes fail DNS lookups while cURL still has outbound
     * connectivity. Fall back to public DNS-over-HTTPS so SSRF checks can still validate
     * that the final host resolves only to public IPs.
     *
     * @return list<string>
     */
    private static function resolveHostIpsViaDoh(string $host): array
    {
        if (!preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i', $host)) {
            return [];
        }

        $queries = [
            ['url' => 'https://dns.google/resolve?name=' . rawurlencode($host) . '&type=A',    'accept' => 'application/json'],
            ['url' => 'https://dns.google/resolve?name=' . rawurlencode($host) . '&type=AAAA', 'accept' => 'application/json'],
            ['url' => 'https://cloudflare-dns.com/dns-query?name=' . rawurlencode($host) . '&type=A',    'accept' => 'application/dns-json'],
            ['url' => 'https://cloudflare-dns.com/dns-query?name=' . rawurlencode($host) . '&type=AAAA', 'accept' => 'application/dns-json'],
        ];

        $ips = [];
        foreach ($queries as $query) {
            $ch = curl_init($query['url']);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 2,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HTTPHEADER     => [
                    'Accept: ' . $query['accept'],
                    'User-Agent: ' . AP_SOFTWARE . '/' . AP_VERSION . ' (+https://' . AP_DOMAIN . ')',
                ],
            ]);
            $raw = curl_exec($ch);
            self::closeCurlHandle($ch);
            if (!is_string($raw) || $raw === '') continue;

            $json = json_decode($raw, true);
            if (!is_array($json)) continue;
            foreach (($json['Answer'] ?? []) as $answer) {
                $ip = (string)($answer['data'] ?? '');
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $ips[] = $ip;
                }
            }
        }

        return array_values(array_unique($ips));
    }

    private static function dnsCachePath(string $host): string
    {
        $dir = ROOT . '/storage/runtime';
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        return $dir . '/dns_' . md5(strtolower($host)) . '.json';
    }

    /**
     * @return array{ips:list<string>,status:string,error:string,source:string}|null
     */
    private static function dnsCacheGet(string $host): ?array
    {
        $path = self::dnsCachePath($host);
        if (!is_file($path)) return null;
        if ((time() - (int)@filemtime($path)) > self::DNS_CACHE_TTL_SECONDS) return null;
        $json = json_decode((string)@file_get_contents($path), true);
        if (!is_array($json) || !isset($json['ips'], $json['status'], $json['error'], $json['source'])) {
            return null;
        }
        return [
            'ips' => array_values(array_filter((array)$json['ips'], static fn($ip) => is_string($ip) && $ip !== '')),
            'status' => (string)$json['status'],
            'error' => (string)$json['error'],
            'source' => (string)$json['source'],
        ];
    }

    /**
     * @param array{ips:list<string>,status:string,error:string,source:string} $result
     */
    private static function dnsCachePut(string $host, array $result): void
    {
        $path = self::dnsCachePath($host);
        @file_put_contents($path, json_encode($result, JSON_UNESCAPED_SLASHES), LOCK_EX);
    }

    /**
     * @return array{records:list<array<string,mixed>>,error:string}
     */
    private static function dnsGetRecordSafe(string $host): array
    {
        $warning = '';
        set_error_handler(static function (int $severity, string $message) use (&$warning): bool {
            $warning = trim($message);
            return true;
        });
        try {
            $records = dns_get_record($host, DNS_A + DNS_AAAA);
        } finally {
            restore_error_handler();
        }

        return [
            'records' => is_array($records) ? $records : [],
            'error' => $warning,
        ];
    }

    private static function classifyDnsError(string $message): string
    {
        $m = strtolower($message);
        if (str_contains($m, 'temporary server error') || str_contains($m, 'try again')) {
            return 'dns_tempfail';
        }
        if (str_contains($m, 'not found') || str_contains($m, 'nxdomain') || str_contains($m, 'no such host')) {
            return 'dns_nxdomain';
        }
        return 'dns_unresolved';
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
            if (($b0 === 0xfe) && (($b1 & 0xc0) === 0x80)) return false; // fe80::/10 link-local
            if (($b0 & 0xfe) === 0xfc) return false;                      // fc00::/7 ULA
        }

        return true;
    }

    /**
     * @return list<array<string,mixed>>
     */
    private static function candidateKeys(mixed $source): array
    {
        if (!is_array($source)) return [];
        if (isset($source['publicKeyPem']) || isset($source['publicKeyMultibase']) || isset($source['id'])) {
            return [$source];
        }
        return array_values(array_filter($source, fn($item) => is_array($item)));
    }

    private static function multibaseToPem(string $multibase): string
    {
        if (!str_starts_with($multibase, 'z')) return '';
        $decoded = self::base58Decode(substr($multibase, 1));
        if ($decoded === '' || strlen($decoded) < 34) return '';

        // Multicodec Ed25519 public key = 0xed 0x01 + 32 raw key bytes.
        if (substr($decoded, 0, 2) !== "\xed\x01") return '';
        $rawKey = substr($decoded, 2, 32);
        if (strlen($rawKey) !== 32) return '';

        $der = hex2bin('302a300506032b6570032100') . $rawKey;
        $b64 = chunk_split(base64_encode($der), 64, "\n");
        return "-----BEGIN PUBLIC KEY-----\n{$b64}-----END PUBLIC KEY-----\n";
    }

    private static function base58Decode(string $input): string
    {
        if ($input === '') return '';
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $indexes  = array_flip(str_split($alphabet));
        $bytes    = [0];

        foreach (str_split($input) as $char) {
            if (!isset($indexes[$char])) return '';
            $carry = $indexes[$char];
            for ($i = count($bytes) - 1; $i >= 0; $i--) {
                $carry += $bytes[$i] * 58;
                $bytes[$i] = $carry & 0xff;
                $carry >>= 8;
            }
            while ($carry > 0) {
                array_unshift($bytes, $carry & 0xff);
                $carry >>= 8;
            }
        }

        $leadingZeros = 0;
        while ($leadingZeros < strlen($input) && $input[$leadingZeros] === '1') {
            $leadingZeros++;
        }

        return str_repeat("\x00", $leadingZeros) . pack('C*', ...$bytes);
    }
}
