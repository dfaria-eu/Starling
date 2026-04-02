<?php
declare(strict_types=1);

namespace App\Models;

class UserModel
{
    private static array $countSyncCache = [];

    private static function activeLocalStatusCond(): string
    {
        return 'user_id=? AND local=1 AND (expires_at IS NULL OR expires_at="" OR expires_at>?)';
    }

    private static function byActorUrl(string $actorUrl): ?array
    {
        $host = strtolower((string)(parse_url($actorUrl, PHP_URL_HOST) ?? ''));
        if ($host === '' || !is_local($host)) return null;

        $path = rawurldecode((string)(parse_url($actorUrl, PHP_URL_PATH) ?? ''));
        if (preg_match('~^/users/([^/?#]+)$~', $path, $m)) {
            return self::byUsername($m[1]);
        }
        if (preg_match('~^/@([^/?#]+)$~', $path, $m)) {
            return self::byUsername($m[1]);
        }
        return null;
    }

    public static function create(array $d): array
    {
        [$priv, $pub] = CryptoModel::generateKeyPair();
        $now = now_iso();
        $id  = uuid();

        DB::insert('users', [
            'id'             => $id,
            'username'       => strtolower($d['username']),
            'email'          => strtolower($d['email']),
            'password'       => password_hash($d['password'], PASSWORD_BCRYPT),
            'display_name'   => $d['display_name'] ?? $d['username'],
            'bio'            => $d['bio'] ?? '',
            'avatar'         => $d['avatar'] ?? '',
            'header'         => $d['header'] ?? '',
            'is_admin'       => (int)($d['is_admin'] ?? 0),
            'is_locked'      => (int)($d['is_locked'] ?? 0),
            'is_bot'         => (int)($d['is_bot'] ?? 0),
            'is_suspended'   => 0,
            'follower_count' => 0,
            'following_count'=> 0,
            'status_count'   => 0,
            'private_key'    => $priv,
            'public_key'     => $pub,
            'also_known_as'  => '[]',
            'moved_to'       => '',
            'preferences'    => '{}',
            'fields'         => '[]',
            'discoverable'   => 1,
            'indexable'      => 1,
            'created_at'     => $now,
            'updated_at'     => $now,
        ]);

        return self::byId($id);
    }

    public static function byId(string $id): ?array
    {
        $user = DB::one('SELECT * FROM users WHERE id=?', [$id]);
        return $user ? self::syncMaterializedCounts($user) : null;
    }

    public static function byUsername(string $u): ?array
    {
        $user = DB::one('SELECT * FROM users WHERE username=? AND is_suspended=0', [strtolower($u)]);
        return $user ? self::syncMaterializedCounts($user) : null;
    }

    public static function byUsernameAny(string $u): ?array
    {
        $user = DB::one('SELECT * FROM users WHERE username=?', [strtolower($u)]);
        return $user ? self::syncMaterializedCounts($user) : null;
    }

    public static function byEmail(string $e): ?array
    {
        $user = DB::one('SELECT * FROM users WHERE email=? AND is_suspended=0', [strtolower($e)]);
        return $user ? self::syncMaterializedCounts($user) : null;
    }

    public static function byEmailAny(string $e): ?array
    {
        $user = DB::one('SELECT * FROM users WHERE email=?', [strtolower($e)]);
        return $user ? self::syncMaterializedCounts($user) : null;
    }

    public static function verify(string $login, string $password): ?array
    {
        $u = self::byUsername($login) ?? self::byEmail($login);
        // Always run password_verify even when user not found to prevent timing-based
        // username enumeration (constant-time response regardless of whether user exists).
        $hash = $u['password'] ?? '$2y$10$invalidhashxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
        if (!password_verify($password, $hash)) return null;
        return $u;
    }

    public static function update(string $id, array $data): void
    {
        $data['updated_at'] = now_iso();
        DB::update('users', $data, 'id=?', [$id]);
        self::invalidateCountSyncCache($id);
    }

    public static function invalidateCountSyncCache(string|array|null $userIds = null): void
    {
        if ($userIds === null) {
            self::$countSyncCache = [];
            return;
        }
        foreach ((array)$userIds as $userId) {
            if (!is_string($userId) || $userId === '') continue;
            unset(self::$countSyncCache[$userId]);
        }
    }

    public static function reconcileCounts(string $userId): ?array
    {
        $user = DB::one('SELECT * FROM users WHERE id=?', [$userId]);
        return $user ? self::syncMaterializedCounts($user, true) : null;
    }

    private static function syncMaterializedCounts(array $user, bool $force = false): array
    {
        $userId = (string)($user['id'] ?? '');
        if ($userId === '') return $user;
        if (!$force && isset(self::$countSyncCache[$userId])) return self::$countSyncCache[$userId];

        $actualFollowers = (int)(DB::one(
            "SELECT COUNT(*) c FROM follows
             WHERE following_id=? AND pending=0
               AND (follower_id LIKE 'http%' OR follower_id NOT IN (SELECT id FROM users WHERE is_suspended=1))",
            [$userId]
        )['c'] ?? 0);
        $actualFollowing = (int)(DB::one(
            "SELECT COUNT(*) c FROM follows
             WHERE follower_id=? AND pending=0
               AND (following_id LIKE 'http%' OR following_id NOT IN (SELECT id FROM users WHERE is_suspended=1))",
            [$userId]
        )['c'] ?? 0);
        $actualStatuses  = DB::count('statuses', self::activeLocalStatusCond(), [$userId, now_iso()]);

        $updates = [];
        if ((int)($user['follower_count'] ?? 0) !== $actualFollowers) $updates['follower_count'] = $actualFollowers;
        if ((int)($user['following_count'] ?? 0) !== $actualFollowing) $updates['following_count'] = $actualFollowing;
        if ((int)($user['status_count'] ?? 0) !== $actualStatuses) $updates['status_count'] = $actualStatuses;

        if ($updates) {
            $updates['updated_at'] = now_iso();
            DB::update('users', $updates, 'id=?', [$userId]);
            foreach ($updates as $k => $v) {
                if ($k !== 'updated_at') $user[$k] = $v;
            }
            $user['updated_at'] = $updates['updated_at'];
        }

        return self::$countSyncCache[$userId] = $user;
    }

    // ── last_status_at cache ────────────────────────────────

    /**
     * Return the date of the user's most recent status (YYYY-MM-DD), or null.
     * Per-request static cache prevents N+1 queries when serializing timelines.
     */
    private static function lastStatusAt(string $userId): ?string
    {
        static $cache = [];
        if (!array_key_exists($userId, $cache)) {
            $row = DB::one(
                'SELECT created_at FROM statuses WHERE ' . self::activeLocalStatusCond() . ' ORDER BY created_at DESC LIMIT 1',
                [$userId, now_iso()]
            );
            $cache[$userId] = ($row && $row['created_at']) ? substr($row['created_at'], 0, 10) : null;
        }
        return $cache[$userId];
    }

    // ── Fields helpers ──────────────────────────────────────

    /**
     * Parse stored JSON fields into the Mastodon API format.
     * Stored as [{"name":"...","value":"..."},...] — max 4 fields.
     */
    public static function parseFields(string $json): array
    {
        $raw = json_decode($json, true);
        if (!is_array($raw)) return [];
        return array_slice(array_map(fn($f) => [
            'name'        => $f['name']  ?? '',
            'value'       => self::fieldValueToHtml($f['value'] ?? ''),
            'verified_at' => $f['verified_at'] ?? null,
        ], array_filter($raw, fn($f) => !empty($f['name']))), 0, 4);
    }

    /**
     * Raw field values for account source/edit forms.
     * Clients expect plain text / plain URLs here, not the HTMLified public representation.
     */
    public static function parseFieldsRaw(string $json): array
    {
        $raw = json_decode($json, true);
        if (!is_array($raw)) return [];
        return array_slice(array_map(fn($f) => [
            'name'        => trim((string)($f['name'] ?? '')),
            'value'       => trim((string)($f['value'] ?? '')),
            'verified_at' => $f['verified_at'] ?? null,
        ], array_filter($raw, fn($f) => !empty($f['name']))), 0, 4);
    }

    /**
     * Convert a field value to HTML for API output.
     * - Already contains HTML (remote accounts send HTML) → return as-is
     * - Plain URL → wrap in <a> tag
     * - Plain text → HTML-escape
     */
    /**
     * Fetch $url and check if it contains a rel="me" link pointing to $actorUrl.
     * Returns ISO timestamp if verified, null otherwise.
     */
    public static function verifyRelMe(string $value, string $actorUrl): ?string
    {
        if (!filter_var($value, FILTER_VALIDATE_URL)) return null;
        if (!str_starts_with($value, 'https://') && !str_starts_with($value, 'http://')) return null;

        // SSRF protection
        $host = parse_url($value, PHP_URL_HOST) ?? '';
        if (!$host) return null;
        $ip = gethostbyname($host);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return null;
        // Explicit block for addresses gethostbyname can't resolve (IPv6 literals passed through)
        // and ranges FILTER_FLAG_NO_PRIV_RANGE may not cover (link-local fe80::/10, ULA fc00::/7).
        if (in_array($ip, ['127.0.0.1', '0.0.0.0', '::1']) || str_starts_with($ip, '169.254.')) return null;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Reject loopback (::1), link-local (fe80::/10), ULA (fc00::/7)
            $iphex = bin2hex(inet_pton($ip) ?: '');
            if (!$iphex) return null;
            $prefix10 = substr($iphex, 0, 3); // first 10 bits = first 10 bits of first 2 hex chars
            $first16  = hexdec(substr($iphex, 0, 4)); // first 16-bit group
            if ($ip === '::1') return null;                              // loopback
            if (($first16 & 0xFFC0) === 0xFE80) return null;            // fe80::/10 link-local
            if (($first16 & 0xFE00) === 0xFC00) return null;            // fc00::/7 unique local
        }

        $ch = curl_init($value);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => AP_SOFTWARE . '/' . AP_VERSION . ' (+https://' . AP_DOMAIN . ')',
            CURLOPT_HTTPHEADER     => ['Accept: text/html'],
        ]);
        $html     = (string)curl_exec($ch);
        $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }

        if (!$html) return null;

        // Check redirect destination for SSRF
        if ($finalUrl && $finalUrl !== $value) {
            $fHost = parse_url($finalUrl, PHP_URL_HOST) ?? '';
            if ($fHost) {
                $fIp = gethostbyname($fHost);
                if (filter_var($fIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return null;
            }
        }

        // All accepted URLs for this profile (both /users/df and /@df formats)
        $username   = parse_url($actorUrl, PHP_URL_PATH);
        $atUrl      = AP_BASE_URL . '/@' . ltrim(basename($username), '@');
        $acceptUrls = [$actorUrl, $atUrl];

        // Look for <a rel="me" href="..."> or <link rel="me" href="...">
        // Use [\s\S] to handle multi-line tags
        if (preg_match_all('/<(?:a|link)([\s\S]*?)(?:>|\/?>)/i', $html, $tags)) {
            foreach ($tags[0] as $tag) {
                $hasRelMe = (bool)preg_match('/\brel=["\'][^"\']*\bme\b[^"\']*["\']/i', $tag);
                if (!$hasRelMe) continue;
                foreach ($acceptUrls as $url) {
                    if (str_contains($tag, $url)) return now_iso();
                }
            }
        }

        return null;
    }

    public static function fieldValueToHtml(string $value): string
    {
        $trimmed = trim($value);
        if ($trimmed === '') return '';
        // Already HTML (e.g. remote accounts send <a href="..."> directly) — sanitise first
        if ($trimmed !== strip_tags($trimmed)) return ensure_html($trimmed);
        // Plain URL — only allow http(s) to prevent javascript:/data: XSS
        if (preg_match('~^https?://~i', $trimmed) && filter_var($trimmed, FILTER_VALIDATE_URL)) {
            $normalized = self::normalizeProfileFieldValue($trimmed);
            $display = htmlspecialchars(ltrim(preg_replace('~^https?://~i', '', $normalized), '/'));
            $href    = htmlspecialchars($normalized);
            return '<a href="' . $href . '" rel="me nofollow noopener noreferrer" target="_blank">' . $display . '</a>';
        }
        // Plain text
        return htmlspecialchars($trimmed);
    }

    public static function normalizeProfileFieldValue(string $value): string
    {
        $trimmed = trim($value);
        if ($trimmed === '') return '';
        if (!preg_match('~^https?://~i', $trimmed)) return $trimmed;
        $normalized = normalize_http_url($trimmed);
        if (preg_match('~^https?://~i', $normalized)) {
            $normalized = preg_replace_callback('~^https?://~i', static fn(array $m): string => strtolower($m[0]), $normalized) ?? $normalized;
        }
        return $normalized;
    }

    // ── Mastodon Account serialisation ──────────────────────

    public static function toMasto(array $u, ?string $viewerId = null, bool $includePrivate = false, int $_depth = 0): array
    {
        $base     = AP_BASE_URL;
        $actorUrl = actor_url($u['username']);

        // Resolve moved_to to account object if set
        $movedTo = null;
        if ($_depth < 1 && !empty($u['moved_to'])) {
            $movedLocal = self::byActorUrl($u['moved_to']);
            if ($movedLocal) {
                $movedTo = self::toMasto($movedLocal, $viewerId, false, $_depth + 1);
            } else {
                $movedActor = DB::one('SELECT * FROM remote_actors WHERE id=?', [$u['moved_to']]);
                if ($movedActor) $movedTo = self::remoteToMasto($movedActor, $_depth + 1);
            }
        }

        // Pinned status count
        $pinnedCount = DB::count('status_pins', 'user_id=?', [$u['id']]);

        // Source fields — only expose if this is the authenticated user
        $source = null;
        $fields = self::parseFields($u['fields'] ?? '[]');

        if ($includePrivate && $viewerId === $u['id']) {
            $prefs = json_decode($u['preferences'] ?? '{}', true) ?: [];
            $source = [
                'privacy'               => $prefs['posting:default:visibility'] ?? 'public',
                'sensitive'             => (bool)($prefs['posting:default:sensitive'] ?? false),
                'language'              => $prefs['posting:default:language'] ?? 'pt',
                'note'                  => $u['bio'] ?? '',
                'fields'                => self::parseFieldsRaw($u['fields'] ?? '[]'),
                'follow_requests_count' => DB::count('follows', 'following_id=? AND pending=1', [$u['id']]),
                'indexable'             => (bool)($u['indexable']    ?? 1),
                'discoverable'          => (bool)($u['discoverable'] ?? 1),
                'hide_collections'     => false,
                'attribution_domains'  => [],
            ];
        }

        $out = [
            'id'              => $u['id'],
            'username'        => $u['username'],
            'acct'            => $u['username'],
            'display_name'    => $u['display_name'],
            'locked'          => (bool)$u['is_locked'],
            'bot'             => (bool)$u['is_bot'],
            'created_at'      => best_iso_timestamp($u['created_at'] ?? null, $u['updated_at'] ?? null, $u['id'] ?? null),
            'note'            => text_to_html($u['bio']),
            'url'             => ap_url('@' . $u['username']),
            'uri'             => $actorUrl,
            'avatar'          => local_media_url_or_fallback($u['avatar'] ?? '', '/img/avatar.svg'),
            'avatar_static'   => local_media_url_or_fallback($u['avatar'] ?? '', '/img/avatar.svg'),
            'header'          => local_media_url_or_fallback($u['header'] ?? '', '/img/header.svg'),
            'header_static'   => local_media_url_or_fallback($u['header'] ?? '', '/img/header.svg'),
            'followers_count' => (int)$u['follower_count'],
            'following_count' => (int)$u['following_count'],
            'statuses_count'  => (int)$u['status_count'],
            'last_status_at'  => self::lastStatusAt($u['id']),
            'emojis'          => [],
            'fields'          => $fields,
            'roles'           => [],
            'group'           => false,
            'discoverable'    => (bool)($u['discoverable'] ?? 1),
            'noindex'         => !((bool)($u['indexable'] ?? 1)),
            'suspended'       => (bool)$u['is_suspended'],
            'limited'         => false,
            'moved'           => $movedTo,
            'also_known_as'   => json_decode($u['also_known_as'] ?? '[]', true) ?: [],
        ];

        if ($source !== null) $out['source'] = $source;
        if ($includePrivate && $viewerId === $u['id']) {
            $out['pleroma'] = ['is_admin' => (bool)($u['is_admin'] ?? false)];
        }

        return $out;
    }

    public static function remoteToMasto(array $a, int $_depth = 0): array
    {
        $base = AP_BASE_URL;

        // Depth limit prevents infinite recursion for circular moved_to chains (A→B→A)
        $movedTo = null;
        if ($_depth < 1 && !empty($a['moved_to'])) {
            $movedLocal = self::byActorUrl($a['moved_to']);
            if ($movedLocal) {
                $movedTo = self::toMasto($movedLocal);
            } else {
                $movedActor = DB::one('SELECT * FROM remote_actors WHERE id=?', [$a['moved_to']]);
                if ($movedActor) $movedTo = self::remoteToMasto($movedActor, $_depth + 1);
            }
        }

        return [
            'id'              => $a['masto_id'] ?: md5($a['id']),
            'username'        => $a['username'],
            'acct'            => $a['username'] . '@' . $a['domain'],
            'display_name'    => $a['display_name'],
            'locked'          => (bool)$a['is_locked'],
            'bot'             => (bool)$a['is_bot'],
            'created_at'      => best_iso_timestamp($a['published_at'] ?? null, $a['fetched_at'] ?? null, null),
            'note'            => ensure_html($a['bio'] ?? ''),
            'url'             => ($a['url'] ?? '') ?: $a['id'],
            'uri'             => $a['id'],
            'avatar'          => $a['avatar']     ?: $base . '/img/avatar.svg',
            'avatar_static'   => $a['avatar']     ?: $base . '/img/avatar.svg',
            'header'          => $a['header_img'] ?: $base . '/img/header.svg',
            'header_static'   => $a['header_img'] ?: $base . '/img/header.svg',
            'followers_count' => (int)$a['follower_count'],
            'following_count' => (int)$a['following_count'],
            'statuses_count'  => (int)$a['status_count'],
            'last_status_at'  => $a['status_count'] > 0 ? self::lastStatusAt($a['id']) : null,
            'emojis'          => [],
            'fields'          => self::parseFields($a['fields'] ?? '[]'),
            'roles'           => [],
            'group'           => false,
            'discoverable'    => true,
            'noindex'         => false,
            'suspended'       => false,
            'limited'         => false,
            'moved'           => $movedTo,
            'also_known_as'   => json_decode($a['also_known_as'] ?? '[]', true) ?: [],
        ];
    }
}
