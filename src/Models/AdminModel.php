<?php
declare(strict_types=1);

namespace App\Models;

class AdminModel
{
    public const AGGRESSIVE_DEFAULTS = [
        'inbox_days'         => 3,
        'remote_posts_days'  => 10,
        'remote_actors_days' => 21,
        'orphan_media_hours' => 6,
        'notifications_days' => 21,
        'tokens_days'        => 45,
        'link_cards_days'    => 7,
        'runtime_days'       => 7,
    ];
    private const VACUUM_MIN_DB_BYTES       = 262144000; // 250 MB
    private const VACUUM_MIN_DELETIONS      = 5000;
    private const VACUUM_AUTO_COOLDOWN_SECS = 172800;    // 48 h
    private const DASHBOARD_HEAVY_CACHE_TTL = 300;
    // ── Autenticação de sessão ────────────────────────────────

    public static function startSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_name('ap_admin');
            session_set_cookie_params([
                'lifetime' => 7200,
                'path'     => '/admin',
                'secure'   => is_https_request(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
            session_start();
        }
    }

    public static function isLoggedIn(): bool
    {
        self::startSession();
        if (empty($_SESSION['admin_user_id'])
            || empty($_SESSION['admin_ip'])
            || $_SESSION['admin_ip'] !== ($_SERVER['REMOTE_ADDR'] ?? '')) {
            return false;
        }
        return self::currentAdmin() !== null;
    }

    public static function login(string $username, string $password): bool
    {
        self::startSession();
        $u = UserModel::byUsername($username);
        if (!$u || !$u['is_admin']) return false;
        if (!password_verify($password, $u['password'])) return false;
        session_regenerate_id(true);
        $_SESSION['admin_user_id'] = $u['id'];
        $_SESSION['admin_username'] = $u['username'];
        $_SESSION['admin_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
        return true;
    }

    public static function logout(): void
    {
        self::startSession();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires'  => time() - 3600,
                'path'     => $params['path'] ?: '/admin',
                'domain'   => $params['domain'] ?: '',
                'secure'   => (bool)($params['secure'] ?? false),
                'httponly' => (bool)($params['httponly'] ?? true),
                'samesite' => $params['samesite'] ?? 'Strict',
            ]);
        }
        session_destroy();
    }

    public static function currentAdmin(): ?array
    {
        self::startSession();
        if (empty($_SESSION['admin_user_id'])) return null;
        $user = UserModel::byId($_SESSION['admin_user_id']);
        if (!$user || empty($user['is_admin']) || !empty($user['is_suspended'])) {
            $_SESSION = [];
            return null;
        }
        return $user;
    }

    // ── Dashboard — estatísticas gerais ─────────────────────

    public static function dashboardStats(): array
    {
        $db = DB::pdo();
        $now = now_iso();
        $activeStatusCond = "(expires_at IS NULL OR expires_at='' OR expires_at>?)";

        // Contagens básicas
        $users       = DB::count('users', 'is_suspended=0');
        $admins      = DB::count('users', 'is_admin=1');
        $suspended   = DB::count('users', 'is_suspended=1');
        $localPosts  = DB::count('statuses', "local=1 AND $activeStatusCond", [$now]);
        $remotePosts = DB::count('statuses', "local=0 AND $activeStatusCond", [$now]);
        $follows     = DB::count('follows', '1');
        $pending     = DB::count('follows', 'pending=1');
        $remoteActors= DB::count('remote_actors', '1');
        $domains     = DB::one("SELECT COUNT(DISTINCT domain) n FROM remote_actors WHERE domain != ?", [AP_DOMAIN])['n'] ?? 0;
        $inboxLog    = DB::count('inbox_log', '1');
        $mediaFiles  = DB::count('media_attachments', '1');
        $blocked     = DB::count('domain_blocks', '1');

        // Actividade recente (últimas 24h)
        $since24h = gmdate('Y-m-d\TH:i:s\Z', time() - 86400);
        $newPosts24h  = DB::count('statuses',   "local=1 AND created_at>? AND $activeStatusCond", [$since24h, $now]);
        $newUsers24h  = DB::count('users',       'created_at>?', [$since24h]);
        $inboxItems24h= DB::count('inbox_log',   'created_at>?', [$since24h]);

        $heavy = self::dashboardHeavyStats();
        $dbSize = $heavy['dbSize'];
        $mediaSize = $heavy['mediaSize'];
        $inboxLogSize = $heavy['inboxLogSize'];
        $freeSpace = $heavy['freeSpace'];
        $totalSpace = $heavy['totalSpace'];
        $runtimeSize = self::dirSize(ROOT . '/storage/runtime');
        $starlingStorageFootprint = $dbSize + $mediaSize + $runtimeSize;

        // Posts por dia (últimos 14 dias)
        $chart = [];
        $chartRows = DB::all(
            "SELECT substr(created_at,1,10) day, COUNT(*) n
               FROM statuses
              WHERE local=1
                AND created_at>=?
                AND $activeStatusCond
              GROUP BY substr(created_at,1,10)",
            [gmdate('Y-m-d\TH:i:s\Z', time() - 13 * 86400), $now]
        );
        $chartMap = [];
        foreach ($chartRows as $row) {
            $chartMap[(string)($row['day'] ?? '')] = (int)($row['n'] ?? 0);
        }
        for ($i = 13; $i >= 0; $i--) {
            $day = gmdate('Y-m-d', time() - $i * 86400);
            $chart[] = ['day' => substr($day, 5), 'count' => (int)($chartMap[$day] ?? 0)];
        }

        // Top domínios federados
        $topDomains = $heavy['topDomains'];

        // Erros de inbox recentes
        $inboxErrors = DB::all(
            "SELECT type, COUNT(*) c FROM inbox_log WHERE error!='' GROUP BY type ORDER BY c DESC LIMIT 5"
        );
        $queueTotal = $queueDue = $queueRetrying = $queueFailed = 0;
        $queueOldest = $queueNextDue = $queueLastAttempt = null;
        $queueTopErrors = $queueTopDomains = [];
        try {
            $now = gmdate('Y-m-d\TH:i:s\Z');
            $queueTotal = (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue")['c'] ?? 0);
            $queueDue = (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts<=7 AND next_retry_at<=? AND (processing_until='' OR processing_until<=?)", [$now, $now])['c'] ?? 0);
            $queueRetrying = (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts BETWEEN 1 AND 7")['c'] ?? 0);
            $queueFailed = (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts>=8")['c'] ?? 0);
            $queueOldest = DB::one("SELECT created_at FROM delivery_queue ORDER BY created_at ASC LIMIT 1")['created_at'] ?? null;
            $queueNextDue = DB::one("SELECT next_retry_at FROM delivery_queue WHERE attempts<=7 AND (processing_until='' OR processing_until<=?) ORDER BY next_retry_at ASC LIMIT 1", [$now])['next_retry_at'] ?? null;
            $queueLastAttempt = DB::one("SELECT last_attempt_at FROM delivery_queue WHERE last_attempt_at<>'' ORDER BY last_attempt_at DESC LIMIT 1")['last_attempt_at'] ?? null;
            $queueTopErrors = DB::all(
                "SELECT CASE
                    WHEN last_error_bucket<>'' THEN last_error_bucket
                    WHEN last_error LIKE 'network:%' THEN 'network'
                    WHEN last_http_code BETWEEN 500 AND 599 THEN '5xx'
                    WHEN last_http_code=429 THEN '429'
                    WHEN last_http_code BETWEEN 400 AND 499 THEN '4xx'
                    ELSE 'unknown'
                 END AS bucket, COUNT(*) c
                 FROM delivery_queue
                 WHERE attempts>0
                 GROUP BY bucket
                 ORDER BY c DESC"
            );
            $queueTopDomains = DB::all(
                "SELECT
                    CASE
                        WHEN instr(replace(replace(inbox_url,'https://',''),'http://',''), '/')>0
                            THEN substr(replace(replace(inbox_url,'https://',''),'http://',''),1,instr(replace(replace(inbox_url,'https://',''),'http://',''),'/')-1)
                        ELSE replace(replace(inbox_url,'https://',''),'http://','')
                    END AS domain,
                    COUNT(*) c
                 FROM delivery_queue
                 GROUP BY domain
                 ORDER BY c DESC
                 LIMIT 5"
            );
        } catch (\Throwable) {
        }

        return compact(
            'users','admins','suspended','localPosts','remotePosts',
            'follows','pending','remoteActors','domains',
            'inboxLog','mediaFiles','blocked',
            'newPosts24h','newUsers24h','inboxItems24h',
            'dbSize','mediaSize','inboxLogSize','runtimeSize',
            'freeSpace','totalSpace','starlingStorageFootprint',
            'chart','topDomains','inboxErrors',
            'queueTotal','queueDue','queueRetrying','queueFailed','queueOldest','queueNextDue','queueLastAttempt','queueTopErrors','queueTopDomains'
        );
    }

    private static function dashboardHeavyCachePath(): string
    {
        return ROOT . '/storage/runtime/admin_dashboard_heavy.json';
    }

    private static function dashboardHeavyStats(): array
    {
        $defaults = [
            'dbSize' => 0,
            'mediaSize' => 0,
            'inboxLogSize' => 0,
            'freeSpace' => 0,
            'totalSpace' => 0,
            'topDomains' => [],
        ];

        $path = self::dashboardHeavyCachePath();
        try {
            if (is_file($path) && (time() - (int)@filemtime($path)) < self::DASHBOARD_HEAVY_CACHE_TTL) {
                $cached = json_decode((string)@file_get_contents($path), true);
                if (is_array($cached)) {
                    return array_merge($defaults, $cached);
                }
            }
        } catch (\Throwable) {
        }

        $dbSize = file_exists(AP_DB_PATH) ? (int)filesize(AP_DB_PATH) : 0;
        $mediaSize = self::dirSize(AP_MEDIA_DIR);
        $inboxLogSize = (int)(DB::one("SELECT SUM(LENGTH(raw_json)) n FROM inbox_log")['n'] ?? 0);
        $basePath = is_dir(AP_MEDIA_DIR) ? AP_MEDIA_DIR : dirname(AP_DB_PATH);
        $freeSpace = (int)(@disk_free_space($basePath) ?: 0);
        $totalSpace = (int)(@disk_total_space($basePath) ?: 0);
        $topDomains = DB::all(
            "SELECT domain, COUNT(*) c FROM remote_actors WHERE domain != ? GROUP BY domain ORDER BY c DESC LIMIT 8",
            [AP_DOMAIN]
        );

        $data = compact('dbSize', 'mediaSize', 'inboxLogSize', 'freeSpace', 'totalSpace', 'topDomains');
        try {
            $dir = dirname($path);
            if (!is_dir($dir)) @mkdir($dir, 0755, true);
            @file_put_contents($path, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
        } catch (\Throwable) {
        }

        return $data;
    }

    public static function deliveryQueueOverview(int $limit = 200): array
    {
        $limit = max(20, min($limit, 500));
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $rows = DB::all(
            "SELECT * FROM delivery_queue ORDER BY attempts ASC, next_retry_at ASC LIMIT ?",
            [$limit]
        );
        $stats = [
            'pending'      => (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts=0")['c'] ?? 0),
            'retrying'     => (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts BETWEEN 1 AND 7")['c'] ?? 0),
            'failed'       => (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts>=8")['c'] ?? 0),
            'due'          => (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts<=7 AND next_retry_at<=? AND (processing_until='' OR processing_until<=?)", [$now, $now])['c'] ?? 0),
            'next_due'     => DB::one("SELECT next_retry_at FROM delivery_queue WHERE attempts<=7 AND (processing_until='' OR processing_until<=?) ORDER BY next_retry_at ASC LIMIT 1", [$now])['next_retry_at'] ?? null,
            'last_attempt' => DB::one("SELECT last_attempt_at FROM delivery_queue WHERE last_attempt_at<>'' ORDER BY last_attempt_at DESC LIMIT 1")['last_attempt_at'] ?? null,
            'total'        => (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue")['c'] ?? 0),
            'resolved_recent' => 0,
        ];
        $errorBuckets = DB::all(
            "SELECT CASE
                WHEN last_error_bucket<>'' THEN last_error_bucket
                WHEN last_error LIKE 'network:%' THEN 'network'
                WHEN last_http_code BETWEEN 500 AND 599 THEN '5xx'
                WHEN last_http_code=429 THEN '429'
                WHEN last_http_code BETWEEN 400 AND 499 THEN '4xx'
                WHEN attempts=0 THEN 'pending'
                ELSE 'unknown'
             END AS bucket, COUNT(*) c
             FROM delivery_queue
             GROUP BY bucket
             ORDER BY c DESC"
        );
        $topDomains = DB::all(
            "SELECT
                CASE
                    WHEN instr(replace(replace(inbox_url,'https://',''),'http://',''), '/')>0
                        THEN substr(replace(replace(inbox_url,'https://',''),'http://',''),1,instr(replace(replace(inbox_url,'https://',''),'http://',''),'/')-1)
                    ELSE replace(replace(inbox_url,'https://',''),'http://','')
                END AS domain,
                COUNT(*) c,
                SUM(CASE WHEN attempts>=8 THEN 1 ELSE 0 END) failed
             FROM delivery_queue
             GROUP BY domain
             ORDER BY c DESC
             LIMIT 8"
        );
        $recentAttempts = [];
        $recentBatches = [];
        $batchStats = [
            'count_24h' => 0,
            'slow_24h' => 0,
            'avg_duration_s' => 0.0,
            'p95_duration_s' => 0.0,
            'max_duration_s' => 0.0,
        ];
        try {
            $recentAttempts = DB::all(
                "SELECT *
                   FROM delivery_attempt_log
                  ORDER BY created_at DESC
                  LIMIT 40"
            );
            $stats['resolved_recent'] = (int)(DB::one(
                "SELECT COUNT(*) c
                   FROM delivery_attempt_log
                  WHERE outcome='success'
                    AND created_at>?",
                [gmdate('Y-m-d\TH:i:s\Z', time() - 86400)]
            )['c'] ?? 0);
        } catch (\Throwable) {
        }
        try {
            $recentBatches = DB::all(
                "SELECT *
                   FROM delivery_batch_log
                  ORDER BY created_at DESC
                  LIMIT 30"
            );
            $durations = array_map(
                static fn(array $row): float => max(0.0, ((int)($row['duration_ms'] ?? 0)) / 1000),
                DB::all(
                    "SELECT duration_ms
                       FROM delivery_batch_log
                      WHERE created_at>?
                      ORDER BY duration_ms ASC",
                    [gmdate('Y-m-d\TH:i:s\Z', time() - 86400)]
                )
            );
            $count = count($durations);
            if ($count > 0) {
                $batchStats['count_24h'] = $count;
                $batchStats['slow_24h'] = count(array_filter($durations, static fn(float $s): bool => $s >= 5.0));
                $batchStats['avg_duration_s'] = array_sum($durations) / $count;
                $batchStats['max_duration_s'] = max($durations);
                $p95Index = max(0, (int)ceil($count * 0.95) - 1);
                $batchStats['p95_duration_s'] = $durations[$p95Index] ?? end($durations) ?: 0.0;
            }
        } catch (\Throwable) {
        }
        return [
            'rows' => $rows,
            'stats' => $stats,
            'errorBuckets' => $errorBuckets,
            'topDomains' => $topDomains,
            'recentAttempts' => $recentAttempts,
            'recentBatches' => $recentBatches,
            'batchStats' => $batchStats,
            'tuning' => self::deliveryQueueTuning(),
            'profiles' => self::deliveryQueueProfiles(),
            'matchedProfile' => self::matchDeliveryQueueProfile(self::deliveryQueueTuning()),
        ];
    }

    public static function deliveryQueueProfiles(): array
    {
        return [
            'shared_conservative' => [
                'label' => 'Shared Hosting Conservative',
                'description' => 'Lower peaks and less inline work; best for tight hosting limits.',
                'values' => [
                    'internal_wake_batch' => 10,
                    'request_drain_batch' => 1,
                    'inbox_drain_batch' => 3,
                    'wake_fallback_batch' => 6,
                    'wake_fallback_cycles' => 1,
                    'delivery_connect_timeout' => 3,
                    'delivery_timeout' => 6,
                ],
            ],
            'shared_balanced' => [
                'label' => 'Shared Hosting Balanced',
                'description' => 'More throughput without drifting back into overly long batches.',
                'values' => [
                    'internal_wake_batch' => 12,
                    'request_drain_batch' => 2,
                    'inbox_drain_batch' => 4,
                    'wake_fallback_batch' => 8,
                    'wake_fallback_cycles' => 1,
                    'delivery_connect_timeout' => 4,
                    'delivery_timeout' => 7,
                ],
            ],
            'vps_small' => [
                'label' => 'Small VPS',
                'description' => 'More aggressive for hosts with extra CPU and I/O headroom.',
                'values' => [
                    'internal_wake_batch' => 15,
                    'request_drain_batch' => 3,
                    'inbox_drain_batch' => 5,
                    'wake_fallback_batch' => 10,
                    'wake_fallback_cycles' => 2,
                    'delivery_connect_timeout' => 4,
                    'delivery_timeout' => 8,
                ],
            ],
            'vps_dedicated' => [
                'label' => 'VPS / Dedicated',
                'description' => 'Most aggressive profile for environments with plenty of headroom.',
                'values' => [
                    'internal_wake_batch' => 20,
                    'request_drain_batch' => 4,
                    'inbox_drain_batch' => 8,
                    'wake_fallback_batch' => 12,
                    'wake_fallback_cycles' => 2,
                    'delivery_connect_timeout' => 5,
                    'delivery_timeout' => 10,
                ],
            ],
        ];
    }

    public static function defaultDeliveryQueueTuning(): array
    {
        return self::deliveryQueueProfiles()['shared_conservative']['values'];
    }

    public static function deliveryQueueTuning(): array
    {
        $defaults = self::defaultDeliveryQueueTuning();
        $row = self::instanceContent('delivery_queue_tuning');
        $saved = json_decode((string)($row['body'] ?? '{}'), true);
        if (!is_array($saved)) return $defaults;

        $out = [];
        foreach ($defaults as $key => $default) {
            $value = $saved[$key] ?? $default;
            $out[$key] = max(1, (int)$value);
        }
        return $out;
    }

    public static function matchDeliveryQueueProfile(array $values): string
    {
        foreach (self::deliveryQueueProfiles() as $key => $profile) {
            if (($profile['values'] ?? []) === $values) return $key;
        }
        return 'custom';
    }

    public static function saveDeliveryQueueTuning(array $input, string $adminId, string $preset = 'custom'): array
    {
        $profiles = self::deliveryQueueProfiles();
        $defaults = self::defaultDeliveryQueueTuning();
        $values = $defaults;

        if ($preset !== 'custom' && isset($profiles[$preset])) {
            $values = $profiles[$preset]['values'];
        } else {
            foreach ($defaults as $key => $default) {
                $value = max(1, (int)($input[$key] ?? $default));
                $values[$key] = match ($key) {
                    'request_drain_batch' => min($value, 10),
                    'inbox_drain_batch' => min($value, 20),
                    'internal_wake_batch' => min($value, 50),
                    'wake_fallback_batch' => min($value, 25),
                    'wake_fallback_cycles' => min($value, 5),
                    'delivery_connect_timeout' => min($value, 15),
                    'delivery_timeout' => min($value, 30),
                    default => $value,
                };
            }
            if ($values['delivery_timeout'] < $values['delivery_connect_timeout']) {
                $values['delivery_timeout'] = $values['delivery_connect_timeout'];
            }
        }

        self::saveInstanceContent(
            'delivery_queue_tuning',
            'Delivery queue tuning',
            json_encode($values, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}',
            'json',
            $adminId
        );

        return $values;
    }

    // ── Gestão de utilizadores ───────────────────────────────

    public static function listUsers(int $page = 1, string $q = '', string $filter = 'all'): array
    {
        $limit  = 25;
        $offset = ($page - 1) * $limit;
        $where  = '1=1';
        $params = [];

        if ($q) {
            $where  .= ' AND (username LIKE ? OR email LIKE ? OR display_name LIKE ?)';
            $params  = ["%$q%", "%$q%", "%$q%"];
        }
        if ($filter === 'admin')     { $where .= ' AND is_admin=1'; }
        if ($filter === 'suspended') { $where .= ' AND is_suspended=1'; }
        if ($filter === 'active')    { $where .= ' AND is_suspended=0'; }

        $total = DB::count('users', $where, $params);
        $rows  = DB::all(
            "SELECT id,username,email,display_name,is_admin,is_suspended,is_bot,is_locked,
                    follower_count,following_count,status_count,created_at
             FROM users WHERE $where ORDER BY created_at DESC LIMIT $limit OFFSET $offset",
            $params
        );

        return ['rows' => $rows, 'total' => $total, 'page' => $page, 'pages' => (int)ceil($total / $limit)];
    }

    public static function suspendUser(string $id, bool $suspend): void
    {
        if ($suspend && self::wouldRemoveLastActiveAdmin($id, 'suspend')) {
            throw new \RuntimeException('Cannot suspend the last active administrator account.');
        }
        DB::update('users', ['is_suspended' => $suspend ? 1 : 0, 'updated_at' => now_iso()], 'id=?', [$id]);
        // Revoke all OAuth tokens so the suspended user cannot continue using the API
        if ($suspend) {
            DB::delete('oauth_tokens', 'user_id=?', [$id]);
        }
    }

    public static function toggleAdmin(string $id): void
    {
        $u = UserModel::byId($id);
        if (!$u) return;
        if (!empty($u['is_admin']) && self::wouldRemoveLastActiveAdmin($id, 'demote')) {
            throw new \RuntimeException('Cannot remove administrator access from the last active administrator account.');
        }
        DB::update('users', ['is_admin' => $u['is_admin'] ? 0 : 1, 'updated_at' => now_iso()], 'id=?', [$id]);
    }

    public static function deleteUser(string $id): void
    {
        if (self::wouldRemoveLastActiveAdmin($id, 'delete')) {
            throw new \RuntimeException('Cannot delete the last active administrator account.');
        }
        $affectedUserIds = array_values(array_unique(array_filter(array_merge(
            array_column(DB::all('SELECT follower_id FROM follows WHERE following_id=? AND follower_id<>?', [$id, $id]), 'follower_id'),
            array_column(DB::all('SELECT following_id FROM follows WHERE follower_id=? AND following_id<>?', [$id, $id]), 'following_id')
        ))));
        $affectedStatusIds = array_values(array_unique(array_filter(array_merge(
            array_column(DB::all('SELECT status_id FROM favourites WHERE user_id=?', [$id]), 'status_id'),
            array_column(DB::all('SELECT status_id FROM reblogs WHERE user_id=?', [$id]), 'status_id'),
            array_column(DB::all('SELECT reply_to_id FROM statuses WHERE user_id=? AND reply_to_id IS NOT NULL AND reply_to_id<>""', [$id]), 'reply_to_id'),
            array_column(DB::all('SELECT reblog_of_id FROM statuses WHERE user_id=? AND reblog_of_id IS NOT NULL AND reblog_of_id<>""', [$id]), 'reblog_of_id')
        ))));
        $mediaRows = DB::all('SELECT url, preview_url FROM media_attachments WHERE user_id=?', [$id]);
        $statusIds = array_column(DB::all('SELECT id FROM statuses WHERE user_id=?', [$id]), 'id');
        foreach (array_chunk($statusIds, 200) as $chunk) {
            $ph = implode(',', array_fill(0, count($chunk), '?'));
            DB::run("UPDATE statuses SET quote_of_id=NULL WHERE quote_of_id IN ($ph)", $chunk);
            DB::run("DELETE FROM status_edits     WHERE status_id IN ($ph)", $chunk);
            DB::run("DELETE FROM status_pins      WHERE status_id IN ($ph)", $chunk);
            DB::run("DELETE FROM status_media     WHERE status_id IN ($ph)", $chunk);
            DB::run("DELETE FROM status_hashtags  WHERE status_id IN ($ph)", $chunk);
            DB::run("DELETE FROM favourites       WHERE status_id IN ($ph)", $chunk);
            DB::run("DELETE FROM bookmarks        WHERE status_id IN ($ph)", $chunk);
            DB::run("DELETE FROM notifications    WHERE status_id IN ($ph)", $chunk);
            DB::run("DELETE FROM reblogs          WHERE status_id IN ($ph) OR reblog_status_id IN ($ph)", array_merge($chunk, $chunk));
            DB::run("DELETE FROM statuses         WHERE reblog_of_id IN ($ph)", $chunk);
            DB::run("DELETE FROM statuses         WHERE id IN ($ph)", $chunk);
        }
        foreach ($mediaRows as $m) {
            foreach ([$m['url'] ?? '', $m['preview_url'] ?? ''] as $mediaUrl) {
                if (!is_string($mediaUrl) || $mediaUrl === '') continue;
                $path = self::mediaPathFromUrl($mediaUrl);
                if ($path === null) continue;
                if (is_file($path)) @unlink($path);
            }
        }
        DB::delete('follows',       'follower_id=? OR following_id=?', [$id, $id]);
        DB::delete('favourites',    'user_id=?', [$id]);
        DB::delete('reblogs',       'user_id=?', [$id]);
        DB::delete('bookmarks',     'user_id=?', [$id]);
        DB::delete('notifications', 'user_id=? OR from_acct_id=?', [$id, $id]);
        DB::delete('account_endorsements', 'user_id=? OR target_id=?', [$id, $id]);
        DB::delete('account_notes',        'user_id=? OR target_id=?', [$id, $id]);
        DB::delete('blocks',        'user_id=? OR target_id=?', [$id, $id]);
        DB::delete('mutes',         'user_id=? OR target_id=?', [$id, $id]);
        $listIds = array_column(DB::all('SELECT id FROM lists WHERE user_id=?', [$id]), 'id');
        foreach (array_chunk($listIds, 200) as $chunk) {
            $ph = implode(',', array_fill(0, count($chunk), '?'));
            DB::run("DELETE FROM list_accounts WHERE list_id IN ($ph)", $chunk);
        }
        DB::delete('lists',         'user_id=?', [$id]);
        DB::delete('list_accounts', 'account_id=?', [$id]);
        DB::delete('markers',       'user_id=?', [$id]);
        DB::delete('tag_follows',   'user_id=?', [$id]);
        DB::delete('featured_tags', 'user_id=?', [$id]);
        DB::delete('user_domain_blocks', 'user_id=?', [$id]);
        $filterIds = array_column(DB::all('SELECT id FROM filters WHERE user_id=?', [$id]), 'id');
        foreach (array_chunk($filterIds, 200) as $chunk) {
            $ph = implode(',', array_fill(0, count($chunk), '?'));
            DB::run("DELETE FROM filter_keywords WHERE filter_id IN ($ph)", $chunk);
        }
        DB::delete('filters',       'user_id=?', [$id]);
        DB::delete('media_attachments', 'user_id=?', [$id]);
        DB::delete('oauth_codes',   'user_id=?', [$id]);
        DB::delete('oauth_tokens',  'user_id=?', [$id]);
        DB::delete('users',         'id=?', [$id]);
        self::reconcileStatusCounters($affectedStatusIds);
        foreach ($affectedUserIds as $userId) {
            UserModel::reconcileCounts((string)$userId);
        }
    }

    private static function wouldRemoveLastActiveAdmin(string $id, string $mode): bool
    {
        $user = DB::one('SELECT id, is_admin, is_suspended FROM users WHERE id=?', [$id]);
        if (!$user || empty($user['is_admin']) || !empty($user['is_suspended']) && $mode !== 'delete') {
            return false;
        }
        $activeAdmins = (int)DB::count('users', 'is_admin=1 AND is_suspended=0');
        return $activeAdmins <= 1 && empty($user['is_suspended']);
    }

    private static function reconcileStatusCounters(array $statusIds): void
    {
        $statusIds = array_values(array_unique(array_filter(array_map(
            static fn($id) => is_string($id) && $id !== '' ? $id : null,
            $statusIds
        ))));
        foreach ($statusIds as $statusId) {
            if (!DB::one('SELECT id FROM statuses WHERE id=?', [$statusId])) continue;
            $replyCount = (int)(DB::one('SELECT COUNT(*) c FROM statuses WHERE reply_to_id=?', [$statusId])['c'] ?? 0);
            $reblogCount = (int)(DB::one('SELECT COUNT(*) c FROM statuses WHERE reblog_of_id=?', [$statusId])['c'] ?? 0);
            $favouriteCount = (int)(DB::one('SELECT COUNT(*) c FROM favourites WHERE status_id=?', [$statusId])['c'] ?? 0);
            DB::update('statuses', [
                'reply_count' => $replyCount,
                'reblog_count' => $reblogCount,
                'favourite_count' => $favouriteCount,
            ], 'id=?', [$statusId]);
        }
    }

    // ── Gestão de domínios / federação ───────────────────────

    public static function listDomains(int $page = 1, string $q = ''): array
    {
        $limit  = 30;
        $offset = ($page - 1) * $limit;

        $sql = "SELECT ra.domain,
                       COUNT(*) actor_count,
                       MAX(ra.fetched_at) last_seen,
                       (SELECT 1 FROM domain_blocks db WHERE db.domain=ra.domain LIMIT 1) blocked
                FROM remote_actors ra";
        $params = [];
        $sql .= ' WHERE ra.domain != ?';
        $params[] = AP_DOMAIN;
        if ($q) { $sql .= ' AND ra.domain LIKE ?'; $params[] = "%$q%"; }
        $sql .= " GROUP BY ra.domain ORDER BY actor_count DESC LIMIT $limit OFFSET $offset";

        $rows  = DB::all($sql, $params);
        $totalSql = "SELECT COUNT(DISTINCT domain) n FROM remote_actors WHERE domain != ?";
        $totalParams = [AP_DOMAIN];
        if ($q) {
            $totalSql .= " AND domain LIKE ?";
            $totalParams[] = "%$q%";
        }
        $total = DB::one($totalSql, $totalParams)['n'] ?? 0;

        return ['rows' => $rows, 'total' => (int)$total, 'page' => $page, 'pages' => (int)ceil($total / $limit)];
    }

    public static function blockDomain(string $domain, bool $block, string $adminId): void
    {
        self::ensureDomainBlocksTable();
        if ($block) {
            DB::insertIgnore('domain_blocks', [
                'id'         => uuid(),
                'domain'     => strtolower(trim($domain)),
                'created_by' => $adminId,
                'created_at' => now_iso(),
            ]);
            // Remove follows to/from blocked domain and update local user counters
            $actors = DB::all('SELECT id FROM remote_actors WHERE domain=?', [$domain]);
            foreach ($actors as $a) {
                // Decrement follower_count for local users who were followed by this actor
                DB::run(
                    'UPDATE users SET follower_count = MAX(0, follower_count - 1) WHERE id IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)',
                    [$a['id']]
                );
                // Decrement following_count for local users who were following this actor
                DB::run(
                    'UPDATE users SET following_count = MAX(0, following_count - 1) WHERE id IN (SELECT follower_id FROM follows WHERE following_id=? AND pending=0)',
                    [$a['id']]
                );
                DB::delete('follows', 'follower_id=? OR following_id=?', [$a['id'], $a['id']]);
            }
        } else {
            DB::delete('domain_blocks', 'domain=?', [strtolower(trim($domain))]);
        }
    }

    public static function listBlockedDomains(): array
    {
        self::ensureDomainBlocksTable();
        return DB::all("SELECT db.*, u.username admin_name
                        FROM domain_blocks db
                        LEFT JOIN users u ON u.id=db.created_by
                        ORDER BY db.created_at DESC");
    }

    private static function ensureDomainBlocksTable(): void
    {
        DB::pdo()->exec("CREATE TABLE IF NOT EXISTS domain_blocks (
            id         TEXT PRIMARY KEY,
            domain     TEXT NOT NULL UNIQUE COLLATE NOCASE,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )");
    }

    // ── Inbox log ────────────────────────────────────────────

    public static function inboxLog(int $page = 1, string $type = '', bool $errorsOnly = false): array
    {
        $limit  = 50;
        $offset = ($page - 1) * $limit;
        $where  = '1=1'; $params = [];

        if ($type)       { $where .= ' AND type=?';   $params[] = $type; }
        if ($errorsOnly) { $where .= " AND error!=''"; }

        $total = DB::count('inbox_log', $where, $params);
        $rows  = DB::all(
            "SELECT id,actor_url,type,error,created_at FROM inbox_log
             WHERE $where ORDER BY created_at DESC LIMIT $limit OFFSET $offset",
            $params
        );

        $types = array_column(DB::all("SELECT DISTINCT type FROM inbox_log ORDER BY type"), 'type');

        return ['rows' => $rows, 'total' => $total, 'page' => $page, 'pages' => (int)ceil($total / $limit), 'types' => $types];
    }

    public static function inboxLogDetail(string $id): ?array
    {
        return DB::one('SELECT * FROM inbox_log WHERE id=?', [$id]);
    }

    // ── Manutenção / limpeza ─────────────────────────────────

    /**
     * Apaga entradas do inbox_log mais antigas que $days dias.
     * Devolve número de linhas apagadas.
     */
    public static function pruneInboxLog(int $days): int
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);
        $count  = DB::count('inbox_log', 'created_at<?', [$before]);
        DB::delete('inbox_log', 'created_at<?', [$before]);
        return $count;
    }

    /**
     * Apaga um post remoto específico por URI (e os seus attachments e reblogs).
     * Retorna true se encontrado e apagado, false se não existia.
     */
    public static function deleteRemotePostByUri(string $uri): bool
    {
        $s = DB::one('SELECT * FROM statuses WHERE uri=? AND local=0', [$uri]);
        if (!$s) return false;
        \App\Models\StatusModel::deleteRemote($s['id']);
        return true;
    }

    /**
     * Apaga posts remotos (local=0) mais antigos que $days dias,
     * protegendo posts que alguém segue, marcou, favoritou ou referenciou localmente.
     */
    public static function pruneRemotePosts(int $days): int
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);
        $cond   = "local=0 AND created_at<?
            AND user_id NOT IN (
                SELECT following_id FROM follows
                WHERE follower_id IN (SELECT id FROM users WHERE is_suspended=0)
            )
            AND id NOT IN (SELECT status_id FROM bookmarks)
            AND id NOT IN (
                SELECT status_id FROM favourites
                WHERE user_id IN (SELECT id FROM users)
            )
            AND id NOT IN (
                SELECT reply_to_id FROM statuses
                WHERE local=1 AND reply_to_id IS NOT NULL
            )
            AND id NOT IN (
                SELECT reblog_of_id FROM statuses
                WHERE local=1 AND reblog_of_id IS NOT NULL
            )
            AND id NOT IN (
                SELECT quote_of_id FROM statuses
                WHERE local=1 AND quote_of_id IS NOT NULL
            )";

        // Collect IDs to cascade-delete associated rows first
        $ids = array_column(DB::all("SELECT id FROM statuses WHERE $cond", [$before]), 'id');
        $affectedStatusIds = array_values(array_unique(array_filter(array_merge(
            array_column(DB::all("SELECT reply_to_id FROM statuses WHERE $cond AND reply_to_id IS NOT NULL AND reply_to_id<>''", [$before]), 'reply_to_id'),
            array_column(DB::all("SELECT reblog_of_id FROM statuses WHERE $cond AND reblog_of_id IS NOT NULL AND reblog_of_id<>''", [$before]), 'reblog_of_id')
        ))));
        $count = count($ids);

        if ($ids) {
            // Cascade: clean up related tables before deleting statuses
            foreach (array_chunk($ids, 200) as $chunk) {
                $ph = implode(',', array_fill(0, count($chunk), '?'));
                $mediaRows = DB::all(
                    "SELECT ma.url, ma.preview_url
                     FROM media_attachments ma
                     JOIN status_media sm ON sm.media_id=ma.id
                     WHERE ma.status_id IS NULL AND sm.status_id IN ($ph)",
                    $chunk
                );
                foreach ($mediaRows as $m) {
                    foreach ([$m['url'] ?? '', $m['preview_url'] ?? ''] as $mediaUrl) {
                        if (!is_string($mediaUrl) || $mediaUrl === '') continue;
                        $path = self::mediaPathFromUrl($mediaUrl);
                        if ($path === null) continue;
                        if (is_file($path)) @unlink($path);
                    }
                }
                // Null-out quote_of_id references in other posts
                DB::run("UPDATE statuses SET quote_of_id=NULL WHERE quote_of_id IN ($ph)", $chunk);
                // Delete media_attachments linked via status_media
                DB::run("DELETE FROM media_attachments WHERE id IN (
                    SELECT media_id FROM status_media WHERE status_id IN ($ph)
                )", $chunk);
                DB::run("DELETE FROM status_media    WHERE status_id IN ($ph)", $chunk);
                DB::run("DELETE FROM status_hashtags WHERE status_id IN ($ph)", $chunk);
                DB::run("DELETE FROM favourites      WHERE status_id IN ($ph)", $chunk);
                DB::run("DELETE FROM bookmarks       WHERE status_id IN ($ph)", $chunk);
                DB::run("DELETE FROM notifications   WHERE status_id IN ($ph)", $chunk);
                DB::run("DELETE FROM statuses        WHERE id        IN ($ph)", $chunk);
            }
            self::reconcileStatusCounters($affectedStatusIds);
        }

        return $count;
    }

    /**
     * Remove actores remotos que nenhum utilizador local segue
     * e que não foram vistos há mais de $days dias.
     */
    public static function pruneRemoteActors(int $days): int
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);
        $count  = DB::count('remote_actors',
            "fetched_at<? AND id NOT IN (
                SELECT following_id FROM follows WHERE follower_id IN (SELECT id FROM users)
            ) AND id NOT IN (
                SELECT follower_id FROM follows WHERE following_id IN (SELECT id FROM users)
            ) AND id NOT IN (
                SELECT user_id FROM statuses
            ) AND id NOT IN (
                SELECT target_id FROM account_endorsements
            ) AND id NOT IN (
                SELECT target_id FROM account_notes
            )",
            [$before]
        );
        DB::delete('remote_actors',
            "fetched_at<? AND id NOT IN (
                SELECT following_id FROM follows WHERE follower_id IN (SELECT id FROM users)
            ) AND id NOT IN (
                SELECT follower_id FROM follows WHERE following_id IN (SELECT id FROM users)
            ) AND id NOT IN (
                SELECT user_id FROM statuses
            ) AND id NOT IN (
                SELECT target_id FROM account_endorsements
            ) AND id NOT IN (
                SELECT target_id FROM account_notes
            )",
            [$before]
        );
        return $count;
    }

    /**
     * Remove media não associada a nenhum status (uploads abandonados) 
     * mais antiga que $hours horas.
     */
    public static function pruneOrphanMedia(int $hours = 24): array
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - $hours * 3600);
        $referenced = self::referencedMediaBasenames();
        // Exclude media that is still referenced by status_media (remote posts store
        // attachments with status_id=NULL but link them via status_media)
        $orphans = DB::all(
            "SELECT * FROM media_attachments
             WHERE status_id IS NULL AND created_at<?
             AND id NOT IN (SELECT media_id FROM status_media)",
            [$before]
        );
        $deleted = 0; $freed = 0;
        foreach ($orphans as $m) {
            $paths = array_values(array_unique(array_filter([
                self::mediaPathFromUrl((string)($m['url'] ?? '')),
                self::mediaPathFromUrl((string)($m['preview_url'] ?? '')),
            ])));
            if (!$paths) continue;
            $skip = false;
            foreach ($paths as $path) {
                $base = basename($path);
                if (isset($referenced[$base])) {
                    $skip = true;
                    break;
                }
            }
            if ($skip) continue;
            foreach ($paths as $path) {
                if (is_file($path)) {
                    $freed += (int)filesize($path);
                    @unlink($path);
                }
            }
            DB::delete('media_attachments', 'id=?', [$m['id']]);
            $deleted++;
        }
        return ['files' => $deleted, 'bytes' => $freed];
    }

    /**
     * Remove notificações antigas.
     */
    public static function pruneNotifications(int $days): int
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);
        $count  = DB::count('notifications', 'created_at<?', [$before]);
        DB::delete('notifications', 'created_at<?', [$before]);
        return $count;
    }

    /**
     * Lightweight consistency repair for small auxiliary drifts.
     * Designed for opportunistic execution on shared hosting.
     */
    public static function cleanupDataConsistency(int $limitPerTable = 500): array
    {
        $limitPerTable = max(25, min($limitPerTable, 2000));
        $results = [
            'favourites'   => 0,
            'reblogs'      => 0,
            'status_media' => 0,
            'poll_votes'   => 0,
            'polls_closed' => 0,
            'users_fixed'  => 0,
            'status_times' => 0,
            'notif_times'  => 0,
            'actor_times'  => 0,
            'marker_times' => 0,
            'status_noncanonical_left' => 0,
            'actor_noncanonical_left'  => 0,
        ];

        $deleteByRows = static function (string $sql, callable $deleter) use ($limitPerTable): int {
            $rows = DB::all($sql . ' LIMIT ' . (int)$limitPerTable);
            $n = 0;
            foreach ($rows as $row) {
                $deleter($row);
                $n++;
            }
            return $n;
        };

        $results['favourites'] = $deleteByRows(
            "SELECT f.id
             FROM favourites f
             LEFT JOIN statuses s ON s.id=f.status_id
             WHERE s.id IS NULL",
            static function (array $row): void { DB::delete('favourites', 'id=?', [$row['id']]); }
        );

        $results['reblogs'] = $deleteByRows(
            "SELECT r.id
             FROM reblogs r
             LEFT JOIN statuses s ON s.id=r.status_id
             WHERE s.id IS NULL",
            static function (array $row): void { DB::delete('reblogs', 'id=?', [$row['id']]); }
        );

        $results['status_media'] = $deleteByRows(
            "SELECT sm.status_id, sm.media_id
             FROM status_media sm
             LEFT JOIN statuses s ON s.id=sm.status_id
             WHERE s.id IS NULL",
            static function (array $row): void { DB::delete('status_media', 'status_id=? AND media_id=?', [$row['status_id'], $row['media_id']]); }
        );

        $results['poll_votes'] = $deleteByRows(
            "SELECT pv.id
             FROM poll_votes pv
             LEFT JOIN poll_options po ON po.id=pv.option_id
             WHERE po.id IS NULL",
            static function (array $row): void { DB::delete('poll_votes', 'id=?', [$row['id']]); }
        );

        $results['polls_closed'] = PollModel::closeExpiredPolls(min(100, $limitPerTable));

        foreach (DB::all(
            "SELECT id, created_at, updated_at
             FROM statuses
             WHERE created_at NOT GLOB '????-??-??T??:??:??*.???Z'
                OR updated_at NOT GLOB '????-??-??T??:??:??*.???Z'
             ORDER BY id DESC
             LIMIT " . (int)$limitPerTable
        ) as $row) {
            $created = iso_z((string)($row['created_at'] ?? ''));
            $updated = iso_z((string)($row['updated_at'] ?? ''));
            $normalizedCreated = $created ?? best_iso_timestamp($row['updated_at'] ?? null, null, $row['id'] ?? null);
            $normalizedUpdated = $updated ?? best_iso_timestamp($row['updated_at'] ?? null, $normalizedCreated, $row['id'] ?? null);
            if ($normalizedCreated !== ($row['created_at'] ?? '') || $normalizedUpdated !== ($row['updated_at'] ?? '')) {
                DB::update('statuses', [
                    'created_at' => $normalizedCreated,
                    'updated_at' => $normalizedUpdated,
                ], 'id=?', [$row['id']]);
                $results['status_times']++;
            }
        }

        foreach (DB::all(
            "SELECT id, created_at, read_at
             FROM notifications
             WHERE created_at NOT GLOB '????-??-??T??:??:??*.???Z'
                OR (read_at IS NOT NULL AND read_at<>'' AND read_at NOT GLOB '????-??-??T??:??:??*.???Z')
             ORDER BY id DESC
             LIMIT " . (int)$limitPerTable
        ) as $row) {
            $created = iso_z((string)($row['created_at'] ?? ''));
            $readAt  = iso_z((string)($row['read_at'] ?? ''));
            $update  = [];
            $normalizedCreated = $created ?? flake_iso((string)($row['id'] ?? '')) ?? now_iso();
            if ($normalizedCreated !== ($row['created_at'] ?? '')) $update['created_at'] = $normalizedCreated;
            if (($row['read_at'] ?? null) !== null && ($row['read_at'] ?? '') !== '' && $readAt === null) {
                $update['read_at'] = $normalizedCreated;
            }
            if ($update) {
                DB::update('notifications', $update, 'id=?', [$row['id']]);
                $results['notif_times']++;
            }
        }

        foreach (DB::all(
            "SELECT id, published_at, fetched_at
             FROM remote_actors
             WHERE (published_at IS NOT NULL AND published_at<>'' AND published_at NOT GLOB '????-??-??T??:??:??*.???Z')
                OR fetched_at NOT GLOB '????-??-??T??:??:??*.???Z'
             ORDER BY fetched_at DESC
             LIMIT " . (int)$limitPerTable
        ) as $row) {
            $published = iso_z((string)($row['published_at'] ?? ''));
            $fetched   = iso_z((string)($row['fetched_at'] ?? ''));
            $normalizedFetched = $fetched ?? now_iso();
            $update = [];
            if ($normalizedFetched !== ($row['fetched_at'] ?? '')) $update['fetched_at'] = $normalizedFetched;
            if (($row['published_at'] ?? null) !== null && ($row['published_at'] ?? '') !== '' && $published === null) {
                $update['published_at'] = $normalizedFetched;
            }
            if ($update) {
                DB::update('remote_actors', $update, 'id=?', [$row['id']]);
                $results['actor_times']++;
            }
        }

        foreach (DB::all(
            "SELECT id, updated_at
             FROM markers
             WHERE updated_at NOT GLOB '????-??-??T??:??:??*.???Z'
             ORDER BY updated_at DESC
             LIMIT " . (int)$limitPerTable
        ) as $row) {
            $updated = iso_z((string)($row['updated_at'] ?? ''));
            DB::update('markers', ['updated_at' => $updated ?? now_iso()], 'id=?', [$row['id']]);
            $results['marker_times']++;
        }

        foreach (DB::all('SELECT id, follower_count, following_count, status_count FROM users') as $user) {
            $before = $user;
            $after  = UserModel::reconcileCounts((string)$user['id']);
            if ($after
                && (
                    (int)$before['follower_count'] !== (int)$after['follower_count']
                    || (int)$before['following_count'] !== (int)$after['following_count']
                    || (int)$before['status_count'] !== (int)$after['status_count']
                )
            ) {
                $results['users_fixed']++;
            }
        }

        $results['status_noncanonical_left'] = (int)(DB::one(
            "SELECT COUNT(*) c
             FROM statuses
             WHERE created_at NOT GLOB '????-??-??T??:??:??.???Z'
                OR updated_at NOT GLOB '????-??-??T??:??:??.???Z'"
        )['c'] ?? 0);
        $results['actor_noncanonical_left'] = (int)(DB::one(
            "SELECT COUNT(*) c
             FROM remote_actors
             WHERE (published_at IS NOT NULL AND published_at<>'' AND published_at NOT GLOB '????-??-??T??:??:??.???Z')
                OR fetched_at NOT GLOB '????-??-??T??:??:??.???Z'"
        )['c'] ?? 0);

        return $results;
    }

    /**
     * Executa VACUUM no SQLite para recuperar espaço fisicamente.
     * Pode demorar alguns segundos em bases de dados grandes.
     */
    public static function vacuum(): array
    {
        @set_time_limit(0);
        $before = file_exists(AP_DB_PATH) ? filesize(AP_DB_PATH) : 0;
        DB::pdo()->exec('VACUUM');
        $after  = file_exists(AP_DB_PATH) ? filesize(AP_DB_PATH) : 0;
        return ['before' => $before, 'after' => $after, 'freed' => max(0, $before - $after)];
    }

    private static function vacuumLockPath(): string
    {
        return ROOT . '/storage/runtime/vacuum.lock';
    }

    private static function autoMaintenanceDisabledPath(): string
    {
        return ROOT . '/storage/runtime/auto_maintenance.disabled';
    }

    public static function isAutoMaintenanceEnabled(): bool
    {
        return !is_file(self::autoMaintenanceDisabledPath());
    }

    public static function setAutoMaintenanceEnabled(bool $enabled): void
    {
        $path = self::autoMaintenanceDisabledPath();
        if ($enabled) {
            if (is_file($path)) {
                @unlink($path);
            }
            return;
        }

        if (!is_dir(dirname($path))) {
            @mkdir(dirname($path), 0775, true);
        }
        @file_put_contents($path, "disabled\n");
    }

    public static function vacuumWithLock(): ?array
    {
        $dir = dirname(self::vacuumLockPath());
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        $fh = @fopen(self::vacuumLockPath(), 'c+');
        if (!$fh) return null;
        try {
            if (!flock($fh, LOCK_EX | LOCK_NB)) {
                fclose($fh);
                return null;
            }
            $result = self::vacuum();
            flock($fh, LOCK_UN);
            fclose($fh);
            return $result;
        } catch (\Throwable $e) {
            @flock($fh, LOCK_UN);
            @fclose($fh);
            throw $e;
        }
    }

    /**
     * Remove tokens OAuth expirados / de sessões antigas (> 90 dias).
     */
    public static function pruneOldTokens(int $days = 90): int
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);
        $where  = "COALESCE(NULLIF(last_used,''), created_at)<?";
        $count  = DB::count('oauth_tokens', $where, [$before]);
        DB::delete('oauth_tokens', $where, [$before]);
        return $count;
    }

    /**
     * Remove link cards (cache OGP) mais antigas que $days dias.
     * Podem ser re-obtidas quando o post for partilhado novamente.
     */
    public static function pruneLinkCards(int $days = 30): int
    {
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);
        $where = "fetched_at<? OR image LIKE '/%' OR image LIKE './%' OR image LIKE '../%' OR image LIKE '//%'";
        $count  = DB::count('link_cards', $where, [$before]);
        DB::delete('link_cards', $where, [$before]);
        return $count;
    }

    public static function pruneRuntimeArtifacts(int $days = 7): array
    {
        $days = max(1, min($days, 365));
        $runtimeDir = ROOT . '/storage/runtime';
        $beforeTs = time() - ($days * 86400);
        $deleted = 0;
        $bytes = 0;

        if (!is_dir($runtimeDir)) {
            return ['files' => 0, 'bytes' => 0];
        }

        $targets = [
            'bot_swarm_*.log',
            'bot_swarm_*.json',
            'federated_swarm_*.log',
            'federated_swarm_*.json',
            'dns_*.json',
            'throttle_*.lock',
        ];

        foreach ($targets as $pattern) {
            foreach (glob($runtimeDir . '/' . $pattern) ?: [] as $path) {
                if (!is_file($path)) continue;
                $mtime = (int)@filemtime($path);
                if ($mtime > 0 && $mtime > $beforeTs) continue;
                $bytes += (int)@filesize($path);
                if (@unlink($path)) $deleted++;
            }
        }

        $rateLimitDir = $runtimeDir . '/ratelimit';
        if (is_dir($rateLimitDir)) {
            foreach (glob($rateLimitDir . '/*.json') ?: [] as $path) {
                if (!is_file($path)) continue;
                $mtime = (int)@filemtime($path);
                if ($mtime > 0 && $mtime > $beforeTs) continue;
                $bytes += (int)@filesize($path);
                if (@unlink($path)) $deleted++;
            }
        }

        return ['files' => $deleted, 'bytes' => $bytes];
    }

    public static function pruneDeliveryAttemptLog(int $days = 14): int
    {
        $exists = DB::one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='delivery_attempt_log' LIMIT 1");
        if (!$exists) return 0;
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - ($days * 86400));
        $count = (int)(DB::one('SELECT COUNT(*) c FROM delivery_attempt_log WHERE created_at < ?', [$before])['c'] ?? 0);
        DB::run('DELETE FROM delivery_attempt_log WHERE created_at < ?', [$before]);
        return $count;
    }

    /**
     * Limpeza completa: executa as operações de manutenção com os defaults
     * agressivos, mas sem VACUUM inline. Em shared hosting, juntar deletes
     * grandes e VACUUM no mesmo request aumenta muito o risco de timeout/502.
     */
    public static function pruneAll(): array
    {
        $db = DB::pdo();
        $db->beginTransaction();
        try {
            $results = [
                'inbox'  => self::pruneInboxLog(self::AGGRESSIVE_DEFAULTS['inbox_days']),
                'posts'  => self::pruneRemotePosts(self::AGGRESSIVE_DEFAULTS['remote_posts_days']),
                'actors' => self::pruneRemoteActors(self::AGGRESSIVE_DEFAULTS['remote_actors_days']),
                'notifs' => self::pruneNotifications(self::AGGRESSIVE_DEFAULTS['notifications_days']),
                'media'  => self::pruneOrphanMedia(self::AGGRESSIVE_DEFAULTS['orphan_media_hours']),
                'tokens' => self::pruneOldTokens(self::AGGRESSIVE_DEFAULTS['tokens_days']),
                'cards'  => self::pruneLinkCards(self::AGGRESSIVE_DEFAULTS['link_cards_days']),
                'runtime' => self::pruneRuntimeArtifacts(self::AGGRESSIVE_DEFAULTS['runtime_days']),
                'delivery_log' => self::pruneDeliveryAttemptLog(),
                'consistency' => self::cleanupDataConsistency(),
            ];
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            throw $e;
        }
        return $results;
    }

    public static function shouldVacuumAfterCleanup(array $results): bool
    {
        $deleted = (int)($results['inbox'] ?? 0)
            + (int)($results['posts'] ?? 0)
            + (int)($results['actors'] ?? 0)
            + (int)($results['notifs'] ?? 0)
            + (int)($results['tokens'] ?? 0)
            + (int)($results['cards'] ?? 0)
            + (int)(($results['runtime']['files'] ?? 0))
            + (int)(($results['media']['files'] ?? 0));

        $dbSize = file_exists(AP_DB_PATH) ? filesize(AP_DB_PATH) : 0;
        return $dbSize >= self::VACUUM_MIN_DB_BYTES && $deleted >= self::VACUUM_MIN_DELETIONS;
    }

    /**
     * Shared-host fallback scheduler: runs light cleanup once per day after the
     * configured local hour, and VACUUM once per week (Sunday) after a later hour.
     * It is opportunistic: the first ordinary request in that window triggers it.
     */
    public static function runAutoMaintenanceIfDue(): void
    {
        if (!self::isAutoMaintenanceEnabled()) {
            return;
        }

        if (throttle_allow('auto_maintenance_consistency', 900)) {
            try {
                self::cleanupDataConsistency(150);
            } catch (\Throwable $e) {
                error_log('Auto maintenance consistency failed: ' . $e->getMessage());
            }
        }

        $hour = (int)date('G');
        $day  = date('Y-m-d');

        if ($hour >= 3 && throttle_allow('auto_maintenance_daily:' . $day, 86400)) {
            try {
                $results = [
                    'inbox'  => self::pruneInboxLog(self::AGGRESSIVE_DEFAULTS['inbox_days']),
                    'posts'  => self::pruneRemotePosts(self::AGGRESSIVE_DEFAULTS['remote_posts_days']),
                    'actors' => self::pruneRemoteActors(self::AGGRESSIVE_DEFAULTS['remote_actors_days']),
                    'notifs' => self::pruneNotifications(self::AGGRESSIVE_DEFAULTS['notifications_days']),
                    'media'  => self::pruneOrphanMedia(self::AGGRESSIVE_DEFAULTS['orphan_media_hours']),
                    'tokens' => self::pruneOldTokens(self::AGGRESSIVE_DEFAULTS['tokens_days']),
                    'cards'  => self::pruneLinkCards(self::AGGRESSIVE_DEFAULTS['link_cards_days']),
                    'runtime' => self::pruneRuntimeArtifacts(self::AGGRESSIVE_DEFAULTS['runtime_days']),
                    'delivery_log' => self::pruneDeliveryAttemptLog(),
                    'consistency' => self::cleanupDataConsistency(),
                ];
                if (self::shouldVacuumAfterCleanup($results)
                    && throttle_allow('auto_maintenance_vacuum', self::VACUUM_AUTO_COOLDOWN_SECS)) {
                    self::vacuumWithLock();
                }
            } catch (\Throwable $e) {
                error_log('Auto maintenance daily failed: ' . $e->getMessage());
            }
        }
    }

    // ── Admin action log ─────────────────────────────────────

    public static function logAction(?string $adminId, string $action, string $targetType = '', string $targetId = '', string $summary = '', array $metadata = []): void
    {
        try {
            DB::insert('admin_action_log', [
                'id'            => uuid(),
                'admin_user_id' => (string)$adminId,
                'action'        => $action,
                'target_type'   => $targetType,
                'target_id'     => $targetId,
                'summary'       => $summary,
                'metadata_json' => json_encode($metadata, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}',
                'created_at'    => now_iso(),
            ]);
        } catch (\Throwable) {
        }
    }

    public static function actionLog(int $page = 1): array
    {
        $limit = 50;
        $offset = max(0, ($page - 1) * $limit);
        $total = DB::count('admin_action_log');
        $rows = DB::all(
            "SELECT l.*, u.username AS admin_username
               FROM admin_action_log l
               LEFT JOIN users u ON u.id=l.admin_user_id
              ORDER BY l.created_at DESC
              LIMIT $limit OFFSET $offset"
        );
        return ['rows' => $rows, 'total' => $total, 'page' => $page, 'pages' => (int)max(1, ceil($total / $limit))];
    }

    // ── Instance content / rules ─────────────────────────────

    public static function instanceContent(string $key): ?array
    {
        return DB::one('SELECT * FROM instance_content WHERE content_key=?', [$key]);
    }

    public static function saveInstanceContent(string $key, string $title, string $body, string $format, string $adminId): void
    {
        $existing = self::instanceContent($key);
        $data = [
            'title'      => trim($title),
            'body'       => trim($body),
            'format'     => $format !== '' ? $format : 'text',
            'updated_by' => $adminId,
            'updated_at' => now_iso(),
        ];
        if ($existing) {
            DB::update('instance_content', $data, 'content_key=?', [$key]);
            return;
        }
        DB::insert('instance_content', ['content_key' => $key, ...$data]);
    }

    /** @return array<int,array{id:string,text:string}> */
    public static function instanceRules(): array
    {
        $row = self::instanceContent('rules');
        if (!$row || trim((string)($row['body'] ?? '')) === '') return [];
        $decoded = json_decode((string)$row['body'], true);
        if (!is_array($decoded)) return [];
        $out = [];
        foreach ($decoded as $idx => $rule) {
            $text = trim((string)$rule);
            if ($text === '') continue;
            $out[] = ['id' => (string)($idx + 1), 'text' => $text];
        }
        return $out;
    }

    /** @param array<int,string> $rules */
    public static function saveInstanceRules(array $rules, string $adminId): void
    {
        $clean = [];
        foreach ($rules as $rule) {
            $text = trim((string)$rule);
            if ($text !== '') $clean[] = $text;
        }
        self::saveInstanceContent(
            'rules',
            'Server rules',
            json_encode($clean, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '[]',
            'json',
            $adminId
        );
    }

    // ── Media management ─────────────────────────────────────

    public static function listMedia(int $page = 1, string $q = '', string $type = 'all', bool $orphansOnly = false): array
    {
        $limit = 40;
        $offset = max(0, ($page - 1) * $limit);
        $where = ['1=1'];
        $params = [];

        if ($q !== '') {
            $where[] = '(u.username LIKE ? OR ma.description LIKE ? OR ma.url LIKE ?)';
            $params[] = "%$q%";
            $params[] = "%$q%";
            $params[] = "%$q%";
        }
        if ($type !== 'all') {
            $where[] = 'ma.type=?';
            $params[] = $type;
        }
        if ($orphansOnly) {
            $where[] = 'ma.status_id IS NULL AND sm.status_id IS NULL';
        }

        $whereSql = implode(' AND ', $where);
        $total = (int)(DB::one(
            "SELECT COUNT(*) n
               FROM media_attachments ma
               LEFT JOIN users u ON u.id=ma.user_id
               LEFT JOIN status_media sm ON sm.media_id=ma.id
              WHERE $whereSql",
            $params
        )['n'] ?? 0);
        $rows = DB::all(
            "SELECT ma.*,
                    u.username,
                    COALESCE(ma.status_id, sm.status_id, '') AS attached_status_id
               FROM media_attachments ma
               LEFT JOIN users u ON u.id=ma.user_id
               LEFT JOIN status_media sm ON sm.media_id=ma.id
              WHERE $whereSql
              ORDER BY ma.created_at DESC
              LIMIT $limit OFFSET $offset",
            $params
        );
        $types = array_column(DB::all("SELECT DISTINCT type FROM media_attachments ORDER BY type ASC"), 'type');

        return ['rows' => $rows, 'types' => $types, 'total' => $total, 'page' => $page, 'pages' => (int)max(1, ceil($total / $limit))];
    }

    public static function deleteMedia(string $id): ?array
    {
        $row = DB::one('SELECT * FROM media_attachments WHERE id=?', [$id]);
        if (!$row) return null;

        $deletedFiles = 0;
        $freedBytes = 0;
        foreach ([$row['url'] ?? '', $row['preview_url'] ?? ''] as $mediaUrl) {
            $path = self::mediaPathFromUrl((string)$mediaUrl);
            if ($path !== null && is_file($path)) {
                $freedBytes += (int)filesize($path);
                if (@unlink($path)) $deletedFiles++;
            }
        }

        DB::delete('status_media', 'media_id=?', [$id]);
        DB::delete('media_attachments', 'id=?', [$id]);

        return [
            'id' => (string)$row['id'],
            'url' => (string)($row['url'] ?? ''),
            'type' => (string)($row['type'] ?? ''),
            'files' => $deletedFiles,
            'bytes' => $freedBytes,
        ];
    }

    // ── Reports / moderation ────────────────────────────────

    public static function listReports(int $page = 1, string $status = 'all'): array
    {
        $limit = 40;
        $offset = max(0, ($page - 1) * $limit);
        $where = '1=1';
        $params = [];
        if ($status !== 'all') {
            $where .= ' AND r.status=?';
            $params[] = $status;
        }

        $total = (int)(DB::one("SELECT COUNT(*) n FROM admin_reports r WHERE $where", $params)['n'] ?? 0);
        $rows = DB::all(
            "SELECT r.*,
                    ru.username AS reporter_username,
                    hu.username AS handled_username
               FROM admin_reports r
               LEFT JOIN users ru ON ru.id=r.reporter_id
               LEFT JOIN users hu ON hu.id=r.handled_by
              WHERE $where
              ORDER BY CASE r.status WHEN 'open' THEN 0 WHEN 'investigating' THEN 1 ELSE 2 END, r.created_at DESC
              LIMIT $limit OFFSET $offset",
            $params
        );
        return ['rows' => $rows, 'total' => $total, 'page' => $page, 'pages' => (int)max(1, ceil($total / $limit))];
    }

    public static function createReport(array $data): string
    {
        $id = uuid();
        $now = now_iso();
        DB::insert('admin_reports', [
            'id'                => $id,
            'reporter_id'       => (string)($data['reporter_id'] ?? ''),
            'target_kind'       => (string)($data['target_kind'] ?? 'account'),
            'target_id'         => (string)($data['target_id'] ?? ''),
            'target_label'      => (string)($data['target_label'] ?? ''),
            'reason'            => (string)($data['reason'] ?? ''),
            'comment'           => (string)($data['comment'] ?? ''),
            'status'            => (string)($data['status'] ?? 'open'),
            'moderation_action' => (string)($data['moderation_action'] ?? ''),
            'resolution_note'   => (string)($data['resolution_note'] ?? ''),
            'handled_by'        => (string)($data['handled_by'] ?? ''),
            'handled_at'        => (string)($data['handled_at'] ?? ''),
            'created_at'        => $now,
            'updated_at'        => $now,
        ]);
        return $id;
    }

    public static function reportById(string $id): ?array
    {
        return DB::one('SELECT * FROM admin_reports WHERE id=?', [$id]);
    }

    public static function updateReport(string $id, array $data): void
    {
        $data['updated_at'] = now_iso();
        DB::update('admin_reports', $data, 'id=?', [$id]);
    }

    // ── Disco ─────────────────────────────────────────────────

    public static function diskReport(): array
    {
        $d = self::AGGRESSIVE_DEFAULTS;
        $dbSize     = file_exists(AP_DB_PATH) ? filesize(AP_DB_PATH) : 0;
        $mediaSize  = self::dirSize(AP_MEDIA_DIR);
        $mediaCount = is_dir(AP_MEDIA_DIR) ? count(glob(AP_MEDIA_DIR . '/*')) : 0;
        $runtimeDir = ROOT . '/storage/runtime';
        $runtimeSize = self::dirSize($runtimeDir);
        $runtimeCount = is_dir($runtimeDir)
            ? iterator_count(new \FilesystemIterator($runtimeDir, \FilesystemIterator::SKIP_DOTS))
            : 0;

        // Tamanho por tabela (aproximado via page_count)
        $tableStats = [];
        try {
            $rows = DB::all("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
            foreach ($rows as $r) {
                $n = DB::count($r['name'], '1');
                $tableStats[$r['name']] = $n;
            }
        } catch (\Throwable) {}

        // Espaço potencialmente recuperável / apagável com os defaults atuais
        $inboxBefore     = gmdate('Y-m-d\TH:i:s\Z', time() - $d['inbox_days'] * 86400);
        $remoteBefore    = gmdate('Y-m-d\TH:i:s\Z', time() - $d['remote_posts_days'] * 86400);
        $orphanBefore    = gmdate('Y-m-d\TH:i:s\Z', time() - $d['orphan_media_hours'] * 3600);

        $inboxLogSize    = (int)(DB::one("SELECT SUM(LENGTH(raw_json)) n FROM inbox_log WHERE created_at<?", [$inboxBefore])['n'] ?? 0);
        $remotePostsOld  = DB::count('statuses', "local=0 AND created_at<?", [$remoteBefore]);
        $remotePostsPrunable = count(array_column(DB::all(
            "SELECT id FROM statuses
             WHERE local=0 AND created_at<?
               AND user_id NOT IN (
                   SELECT following_id FROM follows
                   WHERE follower_id IN (SELECT id FROM users WHERE is_suspended=0)
               )
               AND id NOT IN (SELECT status_id FROM bookmarks)
               AND id NOT IN (
                   SELECT status_id FROM favourites
                   WHERE user_id IN (SELECT id FROM users)
               )
               AND id NOT IN (
                   SELECT reply_to_id FROM statuses
                   WHERE local=1 AND reply_to_id IS NOT NULL
               )
               AND id NOT IN (
                   SELECT reblog_of_id FROM statuses
                   WHERE local=1 AND reblog_of_id IS NOT NULL
               )
               AND id NOT IN (
                   SELECT quote_of_id FROM statuses
                   WHERE local=1 AND quote_of_id IS NOT NULL
               )",
            [$remoteBefore]
        ), 'id'));
        $orphanMedia = DB::count(
            'media_attachments',
            "status_id IS NULL AND created_at<? AND id NOT IN (SELECT media_id FROM status_media)",
            [$orphanBefore]
        );
        $runtimePrunable = 0;
        $runtimeBeforeTs = time() - ($d['runtime_days'] * 86400);
        foreach ([
            $runtimeDir . '/bot_swarm_*.log',
            $runtimeDir . '/bot_swarm_*.json',
            $runtimeDir . '/federated_swarm_*.log',
            $runtimeDir . '/federated_swarm_*.json',
            $runtimeDir . '/dns_*.json',
            $runtimeDir . '/throttle_*.lock',
            $runtimeDir . '/ratelimit/*.json',
        ] as $pattern) {
            foreach (glob($pattern) ?: [] as $path) {
                if (!is_file($path)) continue;
                $mtime = (int)@filemtime($path);
                if ($mtime > 0 && $mtime < $runtimeBeforeTs) {
                    $runtimePrunable++;
                }
            }
        }

        $freeSpace = disk_free_space(dirname(AP_DB_PATH)) ?: 0;
        $totalSpace = disk_total_space(dirname(AP_DB_PATH)) ?: 0;

        return compact(
            'dbSize','mediaSize','mediaCount','runtimeSize','runtimeCount',
            'tableStats','inboxLogSize',
            'remotePostsOld','remotePostsPrunable','orphanMedia','runtimePrunable',
            'freeSpace','totalSpace'
        );
    }

    // ── Utilitários ──────────────────────────────────────────

    public static function formatBytes(int $bytes): string
    {
        if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . ' GB';
        if ($bytes >= 1048576)   return round($bytes / 1048576, 2) . ' MB';
        if ($bytes >= 1024)      return round($bytes / 1024, 1) . ' KB';
        return $bytes . ' B';
    }

    private static function dirSize(string $dir): int
    {
        if (!is_dir($dir)) return 0;
        $size = 0;
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)) as $file) {
            $size += $file->getSize();
        }
        return $size;
    }

    private static function mediaPathFromUrl(string $mediaUrl): ?string
    {
        if ($mediaUrl === '') return null;
        $pathPart = parse_url($mediaUrl, PHP_URL_PATH) ?? $mediaUrl;
        $base = basename($pathPart);
        if ($base === '' || $base === '.' || $base === '..') return null;
        return AP_MEDIA_DIR . '/' . $base;
    }

    private static function referencedMediaBasenames(): array
    {
        $names = [];

        $collect = static function (string $url) use (&$names): void {
            if ($url === '') return;
            $pathPart = parse_url($url, PHP_URL_PATH) ?? $url;
            $base = basename($pathPart);
            if ($base !== '' && $base !== '.' && $base !== '..') {
                $names[$base] = true;
            }
        };

        foreach (DB::all('SELECT avatar, header FROM users') as $row) {
            $collect((string)($row['avatar'] ?? ''));
            $collect((string)($row['header'] ?? ''));
        }

        foreach (DB::all('SELECT avatar, header_img FROM remote_actors') as $row) {
            $collect((string)($row['avatar'] ?? ''));
            $collect((string)($row['header_img'] ?? ''));
        }

        return $names;
    }
}
