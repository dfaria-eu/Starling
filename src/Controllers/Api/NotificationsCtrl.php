<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, StatusModel, RemoteActorModel};

class NotificationsCtrl
{
    private const ALLOWED_NOTIF_TYPES = [
        'mention', 'reblog', 'favourite', 'follow', 'follow_request',
        'poll', 'update', 'status', 'direct', 'admin.sign_up',
    ];
    private const POLICY_DEFAULTS = [
        'for_not_following'    => 'accept',
        'for_not_followers'    => 'accept',
        'for_new_accounts'     => 'accept',
        'for_private_mentions' => 'accept',
        'for_limited_accounts' => 'accept',
    ];

    /**
     * Build the WHERE + ORDER + LIMIT portion of a notifications query.
     * Returns [sql_fragment, params].
     */
    private function buildQuery(string $userId, int $limit, ?string $maxId, ?string $sinceId, ?string $minId, ?array $types, array $excl): array
    {
        // Flake IDs are snowflake-based (time-ordered integers as strings, always 17 digits
        // for 2020+ timestamps), so id comparison = chronological comparison.
        // Never use created_at for ordering — mixed formats break string comparison.
        $sql = 'SELECT * FROM notifications WHERE user_id=?';
        $par = [$userId];

        if ($maxId)   { $sql .= ' AND CAST(id AS INTEGER) < CAST(? AS INTEGER)'; $par[] = $maxId; }
        if ($sinceId) { $sql .= ' AND CAST(id AS INTEGER) > CAST(? AS INTEGER)'; $par[] = $sinceId; }
        if ($minId)   { $sql .= ' AND CAST(id AS INTEGER) > CAST(? AS INTEGER)'; $par[] = $minId; }

        if ($types) {
            $sql .= ' AND type IN (' . implode(',', array_fill(0, count($types), '?')) . ')';
            array_push($par, ...$types);
        }
        if ($excl) {
            $sql .= ' AND type NOT IN (' . implode(',', array_fill(0, count($excl), '?')) . ')';
            array_push($par, ...$excl);
        }
        // min_id: oldest-first so client gets the gap, then reverse for display
        $sql .= $minId ? ' ORDER BY CAST(id AS INTEGER) ASC LIMIT ?' : ' ORDER BY CAST(id AS INTEGER) DESC LIMIT ?';
        $par[] = $limit;

        return [$sql, $par];
    }

    /** Parse and whitelist type filter params from $_GET. */
    private function parseTypeFilters(): array
    {
        $types = isset($_GET['types'])
            ? array_values(array_intersect((array)$_GET['types'], self::ALLOWED_NOTIF_TYPES))
            : null;
        $excl = array_values(array_intersect(
            isset($_GET['exclude_types']) ? (array)$_GET['exclude_types'] : [],
            self::ALLOWED_NOTIF_TYPES
        ));
        // null means "no filter"; empty array after intersect means "nothing requested" — treat as no filter too
        if ($types !== null && count($types) === 0) $types = null;
        return [$types, $excl];
    }

    private function groupKeyFor(array $n): string
    {
        $statusScoped = ['mention', 'reblog', 'favourite', 'poll', 'update', 'status', 'direct'];
        if (($n['status_id'] ?? '') !== '' && in_array($n['type'], $statusScoped, true)) {
            return $n['type'] . ':status:' . $n['status_id'];
        }
        if (in_array($n['type'], ['follow', 'follow_request', 'admin.sign_up'], true)) {
            return $n['type'];
        }
        return 'ungrouped-' . $n['id'];
    }

    private function loadPolicy(array $user): array
    {
        $prefs = json_decode($user['preferences'] ?? '{}', true);
        $prefs = is_array($prefs) ? $prefs : [];
        $policy = self::POLICY_DEFAULTS;
        foreach (array_keys(self::POLICY_DEFAULTS) as $key) {
            $value = $prefs['notifications:policy:' . $key] ?? null;
            if (in_array($value, ['accept', 'filter'], true)) {
                $policy[$key] = $value;
            }
        }
        return $policy;
    }

    private function savePolicy(array $user, array $body): array
    {
        $prefs = json_decode($user['preferences'] ?? '{}', true);
        $prefs = is_array($prefs) ? $prefs : [];
        $policy = $this->loadPolicy($user);
        foreach (array_keys(self::POLICY_DEFAULTS) as $key) {
            $value = $body[$key] ?? null;
            if (!in_array($value, ['accept', 'filter'], true)) continue;
            $policy[$key] = $value;
            $prefs['notifications:policy:' . $key] = $value;
        }
        UserModel::update($user['id'], ['preferences' => json_encode($prefs)]);
        return $policy;
    }

    private function relationshipFlags(string $viewerId, string $fromId): array
    {
        static $cache = [];
        $cacheKey = $viewerId . '|' . $fromId;
        if (isset($cache[$cacheKey])) return $cache[$cacheKey];

        $flags = [
            'following'   => false,
            'followed_by' => false,
            'new_account' => false,
            'limited'     => false,
        ];

        $flags['following'] = (bool)DB::one(
            'SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=0',
            [$viewerId, $fromId]
        );
        $flags['followed_by'] = (bool)DB::one(
            'SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=0',
            [$fromId, $viewerId]
        );

        $createdAt = null;
        $local = UserModel::byId($fromId);
        if ($local) {
            $createdAt = $local['created_at'] ?? null;
        } else {
            $remote = DB::one('SELECT published_at FROM remote_actors WHERE id=?', [$fromId]);
            $createdAt = $remote['published_at'] ?? null;
        }
        if ($createdAt) {
            $flags['new_account'] = strtotime((string)$createdAt) >= strtotime('-30 days');
        }

        $cache[$cacheKey] = $flags;
        return $flags;
    }

    private function isHiddenFromViewer(string $viewerId, string $fromId): bool
    {
        if ($fromId === '' || $fromId === $viewerId) return false;
        if (!str_starts_with($fromId, 'http')) {
            $local = UserModel::byId($fromId);
            if ($local && !empty($local['is_suspended'])) return true;
        }
        if (DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$viewerId, $fromId])) return true;
        if (DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$viewerId, $fromId])) return true;
        if (!str_starts_with($fromId, 'http')) return false;
        $ra = DB::one('SELECT domain FROM remote_actors WHERE id=?', [$fromId]);
        if (!$ra || ($ra['domain'] ?? '') === '') return false;
        return (bool)DB::one(
            'SELECT 1 FROM user_domain_blocks WHERE user_id=? AND domain=?',
            [$viewerId, strtolower((string)$ra['domain'])]
        );
    }

    private function isPrivateMentionRequest(array $n): bool
    {
        if (!in_array($n['type'], ['mention', 'direct'], true)) return false;
        if (empty($n['status_id'])) return false;
        $status = StatusModel::byId($n['status_id']);
        if (!$status) return false;
        return in_array($status['visibility'] ?? '', ['private', 'direct'], true);
    }

    private function notificationRequiresRequest(array $n, string $viewerId, array $policy): bool
    {
        if (($n['type'] ?? '') === 'follow_request') return false;
        $flags = $this->relationshipFlags($viewerId, $n['from_acct_id']);

        if ($policy['for_not_following'] === 'filter' && !$flags['following']) return true;
        if ($policy['for_not_followers'] === 'filter' && !$flags['followed_by']) return true;
        if ($policy['for_new_accounts'] === 'filter' && $flags['new_account']) return true;
        if ($policy['for_private_mentions'] === 'filter' && $this->isPrivateMentionRequest($n)) return true;
        if ($policy['for_limited_accounts'] === 'filter' && $flags['limited']) return true;

        return false;
    }

    private function hasRenderableStatus(array $n, string $viewerId): bool
    {
        $statusTypes = ['mention', 'reblog', 'favourite', 'poll', 'update', 'status', 'direct'];
        if (!in_array((string)($n['type'] ?? ''), $statusTypes, true)) {
            return true;
        }
        if (empty($n['status_id'])) {
            return false;
        }
        $status = StatusModel::byId((string)$n['status_id']);
        if (!$status) {
            return false;
        }
        return StatusModel::toMasto($status, $viewerId) !== null;
    }

    private function requestRows(array $user, int $limit, ?string $maxId, ?string $sinceId, ?string $minId, ?array $types, array $excl): array
    {
        $scanLimit = max(200, min(5000, $limit * 20));
        [$sql, $par] = $this->buildQuery($user['id'], $scanLimit, $maxId, $sinceId, $minId, $types, $excl);
        $rows = DB::all($sql, $par);
        if ($minId) $rows = array_reverse($rows);

        $policy = $this->loadPolicy($user);
        $filtered = [];
        foreach ($rows as $row) {
            if (!$this->notificationRequiresRequest($row, $user['id'], $policy)) continue;
            if ($this->isHiddenFromViewer($user['id'], (string)($row['from_acct_id'] ?? ''))) continue;
            if (!$this->hasRenderableStatus($row, $user['id'])) continue;
            $filtered[] = $row;
            if (count($filtered) >= $limit) break;
        }
        return $filtered;
    }

    private function visibleRows(array $user, int $limit, ?string $maxId, ?string $sinceId, ?string $minId, ?array $types, array $excl): array
    {
        $scanLimit = max(200, min(5000, $limit * 20));
        [$sql, $par] = $this->buildQuery($user['id'], $scanLimit, $maxId, $sinceId, $minId, $types, $excl);
        $rows = DB::all($sql, $par);
        if ($minId) $rows = array_reverse($rows);

        $policy = $this->loadPolicy($user);
        $visible = [];
        foreach ($rows as $row) {
            if ($this->notificationRequiresRequest($row, $user['id'], $policy)) continue;
            if ($this->isHiddenFromViewer($user['id'], (string)($row['from_acct_id'] ?? ''))) continue;
            if (!$this->hasRenderableStatus($row, $user['id'])) continue;
            $visible[] = $row;
            if (count($visible) >= $limit) break;
        }
        return $visible;
    }

    private function pendingRequestCount(array $user): int
    {
        [$sql, $par] = $this->buildQuery($user['id'], 5000, null, null, null, null, []);
        $rows = DB::all($sql, $par);
        $policy = $this->loadPolicy($user);
        $count = 0;
        foreach ($rows as $row) {
            if ($this->isHiddenFromViewer($user['id'], (string)($row['from_acct_id'] ?? ''))) continue;
            if (!$this->hasRenderableStatus($row, $user['id'])) continue;
            if ($this->notificationRequiresRequest($row, $user['id'], $policy)) {
                $count++;
            }
        }
        return $count;
    }

    private function backfillReadStateFromMarker(string $userId): void
    {
        static $done = [];
        if (isset($done[$userId])) return;
        $done[$userId] = true;

        $marker = DB::one(
            'SELECT last_read_id, updated_at FROM markers WHERE user_id=? AND timeline=?',
            [$userId, 'notifications']
        );
        $lastReadId = (string)($marker['last_read_id'] ?? '');
        if ($lastReadId === '' || !ctype_digit($lastReadId)) return;

        $readAt = (string)($marker['updated_at'] ?? now_iso());
        DB::run(
            'UPDATE notifications
             SET read_at=COALESCE(read_at, ?)
             WHERE user_id=? AND read_at IS NULL AND CAST(id AS INTEGER) <= CAST(? AS INTEGER)',
            [$readAt, $userId, $lastReadId]
        );
    }

    private function nextNumericNotificationId(string $createdAt): string
    {
        static $seqByMs = [];
        $seq = 0;
        try {
            $dt = new \DateTimeImmutable($createdAt);
            $msKey = $dt->format('Uv');
            $seq = $seqByMs[$msKey] ?? 0;
        } catch (\Throwable) {
            return flake_id();
        }
        do {
            $id = flake_id_at($createdAt, $seq);
            $seq++;
        } while (DB::one('SELECT 1 FROM notifications WHERE id=?', [$id]));
        $seqByMs[$msKey] = $seq;
        return $id;
    }

    private function normalizeNotificationIds(string $userId): void
    {
        static $done = [];
        if (isset($done[$userId])) return;
        $done[$userId] = true;

        if (!throttle_allow('notif_id_normalize:' . $userId, 30)) return;

        $rows = DB::all(
            "SELECT id, created_at
             FROM notifications
             WHERE user_id=? AND id NOT GLOB '[0-9]*'
             ORDER BY created_at ASC
             LIMIT 500",
            [$userId]
        );
        foreach ($rows as $row) {
            $newId = $this->nextNumericNotificationId((string)($row['created_at'] ?? now_iso()));
            DB::update('notifications', ['id' => $newId], 'id=?', [$row['id']]);
        }
    }

    private function backfillMissingEngagementNotifications(string $userId): void
    {
        static $done = [];
        if (isset($done[$userId])) return;
        $done[$userId] = true;

        if (!throttle_allow('notif_backfill:' . $userId, 30)) return;

        $favRows = DB::all(
            "SELECT f.user_id AS from_acct_id, f.status_id, f.created_at
             FROM favourites f
             JOIN statuses s ON s.id=f.status_id
             LEFT JOIN notifications n
               ON n.user_id=s.user_id
              AND n.from_acct_id=f.user_id
              AND n.type='favourite'
              AND n.status_id=s.id
             WHERE s.user_id=?
               AND s.local=1
               AND n.id IS NULL
             ORDER BY f.created_at DESC
             LIMIT 200",
            [$userId]
        );
        foreach ($favRows as $row) {
            DB::insertIgnore('notifications', [
                'id'           => $this->nextNumericNotificationId((string)($row['created_at'] ?? now_iso())),
                'user_id'      => $userId,
                'from_acct_id' => $row['from_acct_id'],
                'type'         => 'favourite',
                'status_id'    => $row['status_id'],
                'read_at'      => null,
                'created_at'   => $row['created_at'] ?: now_iso(),
            ]);
        }

        $reblogRows = DB::all(
            "SELECT st.user_id AS from_acct_id, orig.id AS status_id, st.created_at
             FROM statuses st
             JOIN statuses orig ON orig.id=st.reblog_of_id
             LEFT JOIN notifications n
               ON n.user_id=orig.user_id
              AND n.from_acct_id=st.user_id
              AND n.type='reblog'
              AND n.status_id=orig.id
             WHERE orig.user_id=?
               AND orig.local=1
               AND st.reblog_of_id IS NOT NULL
               AND n.id IS NULL
             ORDER BY st.created_at DESC
             LIMIT 200",
            [$userId]
        );
        foreach ($reblogRows as $row) {
            DB::insertIgnore('notifications', [
                'id'           => $this->nextNumericNotificationId((string)($row['created_at'] ?? now_iso())),
                'user_id'      => $userId,
                'from_acct_id' => $row['from_acct_id'],
                'type'         => 'reblog',
                'status_id'    => $row['status_id'],
                'read_at'      => null,
                'created_at'   => $row['created_at'] ?: now_iso(),
            ]);
        }
    }

    public function index(array $p): void
    {
        $user    = require_auth('read');
        $this->normalizeNotificationIds($user['id']);
        $this->backfillReadStateFromMarker($user['id']);
        $this->backfillMissingEngagementNotifications($user['id']);
        $limit   = min((int)($_GET['limit'] ?? 20), 40);
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;
        [$types, $excl] = $this->parseTypeFilters();

        $rows = $this->visibleRows($user, $limit, $maxId, $sinceId, $minId, $types, $excl);

        $out = array_values(array_filter(array_map(fn($n) => $this->fmtPublic($n, $user), $rows)));

        if ($rows) {
            // Use raw row IDs for pagination cursors so dropped notifications
            // don't corrupt the cursor and cause permanent gaps
            $base       = ap_url('api/v1/notifications');
            $firstId    = reset($rows)['id'];  // newest row fetched
            $lastId     = end($rows)['id'];    // oldest row fetched
            $common     = array_filter([
                'limit' => $limit,
                'types' => $types ?: null,
                'exclude_types' => $excl ?: null,
            ]);
            $nextParams = http_build_query(array_merge($common, ['max_id' => $lastId]));
            $prevParams = http_build_query(array_merge($common, ['min_id' => $firstId]));
            header(sprintf('Link: <%s?%s>; rel="next", <%s?%s>; rel="prev"', $base, $nextParams, $base, $prevParams));
        }
        json_out($out);
    }

    public function show(array $p): void
    {
        $user = require_auth('read');
        $this->normalizeNotificationIds($user['id']);
        $this->backfillReadStateFromMarker($user['id']);
        $this->backfillMissingEngagementNotifications($user['id']);
        $n = DB::one('SELECT * FROM notifications WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$n) err_out('Not found', 404);
        $f = $this->fmtPublic($n, $user);
        if (!$f) err_out('Not found', 404);
        json_out($f);
    }

    public function clear(array $p): void
    {
        $user = require_auth('write');
        DB::delete('notifications', 'user_id=?', [$user['id']]);
        json_out([]);
    }

    public function dismiss(array $p): void
    {
        $user = require_auth('write');
        DB::delete('notifications', 'id=? AND user_id=?', [$p['id'], $user['id']]);
        json_out([]);
    }

    public function indexV2(array $p): void
    {
        $user    = require_auth('read');
        $this->normalizeNotificationIds($user['id']);
        $this->backfillReadStateFromMarker($user['id']);
        $this->backfillMissingEngagementNotifications($user['id']);
        $limit   = min((int)($_GET['limit'] ?? 20), 40);
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;
        [$types, $excl] = $this->parseTypeFilters();

        $rows = $this->visibleRows($user, $limit, $maxId, $sinceId, $minId, $types, $excl);

        if ($rows) {
            $base       = ap_url('api/v2/notifications');
            $firstId    = reset($rows)['id'];
            $lastId     = end($rows)['id'];
            $common     = array_filter([
                'limit' => $limit,
                'types' => $types ?: null,
                'exclude_types' => $excl ?: null,
            ]);
            header(sprintf('Link: <%s?%s>; rel="next", <%s?%s>; rel="prev"',
                $base, http_build_query(array_merge($common, ['max_id' => $lastId])),
                $base, http_build_query(array_merge($common, ['min_id' => $firstId]))
            ));
        }

        $accountsById = [];
        $statusesById = [];
        $groups       = [];

        foreach ($rows as $n) {
            $fmt = $this->fmtPublic($n, $user);
            if (!$fmt) continue;

            $acc = $fmt['account'];
            $accountsById[$acc['id']] = $acc;

            $status = $fmt['status'] ?? null;
            if ($status) $statusesById[$status['id']] = $status;

            $groupKey = $this->groupKeyFor($n);
            if (!isset($groups[$groupKey])) {
                $groups[$groupKey] = [
                    'group_key'                    => $groupKey,
                    'notifications_count'          => 0,
                    'type'                         => $n['type'],
                    'most_recent_notification_id'  => $n['id'],
                    'page_min_id'                  => $n['id'],
                    'page_max_id'                  => $n['id'],
                    'latest_page_notification_ids' => [],
                    'sample_account_ids'           => [],
                    'status_id'                    => $status ? $status['id'] : null,
                    'emoji_reaction'               => null,
                ];
            }
            $groups[$groupKey]['notifications_count']++;
            if ((int)$n['id'] < (int)$groups[$groupKey]['page_min_id']) {
                $groups[$groupKey]['page_min_id'] = $n['id'];
            }
            if ((int)$n['id'] > (int)$groups[$groupKey]['page_max_id']) {
                $groups[$groupKey]['page_max_id'] = $n['id'];
            }
            if (!in_array($n['id'], $groups[$groupKey]['latest_page_notification_ids'], true)) {
                $groups[$groupKey]['latest_page_notification_ids'][] = $n['id'];
            }
            if (!in_array($acc['id'], $groups[$groupKey]['sample_account_ids'], true)) {
                $groups[$groupKey]['sample_account_ids'][] = $acc['id'];
            }
        }

        json_out([
            'accounts'             => array_values($accountsById),
            'statuses'             => array_values($statusesById),
            'notification_groups'  => array_values($groups),
        ]);
    }

    public function policy(array $p): void
    {
        $user = require_auth($_SERVER['REQUEST_METHOD'] === 'PUT' ? 'write' : 'read');
        $this->normalizeNotificationIds($user['id']);
        $this->backfillReadStateFromMarker($user['id']);
        $this->backfillMissingEngagementNotifications($user['id']);
        $policy = $_SERVER['REQUEST_METHOD'] === 'PUT'
            ? $this->savePolicy($user, req_body())
            : $this->loadPolicy($user);
        json_out([
            'for_not_following'    => $policy['for_not_following'],
            'for_not_followers'    => $policy['for_not_followers'],
            'for_new_accounts'     => $policy['for_new_accounts'],
            'for_private_mentions' => $policy['for_private_mentions'],
            'for_limited_accounts' => $policy['for_limited_accounts'],
            'summary' => [
                'pending_requests_count'      => DB::count('follows', 'following_id=? AND pending=1', [$user['id']]),
                'pending_notifications_count' => $this->pendingRequestCount($user),
            ],
        ]);
    }

    public function requests(array $p): void
    {
        $user    = require_auth('read');
        $this->normalizeNotificationIds($user['id']);
        $this->backfillReadStateFromMarker($user['id']);
        $this->backfillMissingEngagementNotifications($user['id']);
        $limit   = min((int)($_GET['limit'] ?? 20), 40);
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;
        [$types, $excl] = $this->parseTypeFilters();

        $rows = $this->requestRows($user, $limit, $maxId, $sinceId, $minId, $types, $excl);
        $out = array_values(array_filter(array_map(fn($n) => $this->fmtPublic($n, $user), $rows)));

        if ($rows) {
            $base    = ap_url('api/v1/notifications/requests');
            $firstId = reset($rows)['id'];
            $lastId  = end($rows)['id'];
            $common  = array_filter([
                'limit' => $limit,
                'types' => $types ?: null,
                'exclude_types' => $excl ?: null,
            ]);
            header(sprintf('Link: <%s?%s>; rel="next", <%s?%s>; rel="prev"',
                $base, http_build_query(array_merge($common, ['max_id' => $lastId])),
                $base, http_build_query(array_merge($common, ['min_id' => $firstId]))
            ));
        }

        json_out($out);
    }

    /**
     * Public wrapper around notification serialization.
     * Used by NotificationsCtrl endpoints and MiscCtrl SSE stream.
     */
    public function fmtPublic(array $n, array $me): ?array
    {
        $fromId  = $n['from_acct_id'];
        $fromAcc = null;

        if ($this->isHiddenFromViewer($me['id'], (string)$fromId)) {
            return null;
        }

        // Per-request cache: avoid duplicate HTTP fetches for the same actor
        // when multiple notifications arrive from the same account.
        static $actorCache = [];
        static $queuedRefresh = [];

        $local = UserModel::byId($fromId);
        if ($local) {
            $fromAcc = UserModel::toMasto($local);
        } else {
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$fromId]);
            if ($ra) {
                if (!isset($actorCache[$fromId])) {
                    $age = time() - (int)strtotime($ra['fetched_at']);
                    $hasZeroCounts = (int)$ra['follower_count'] === 0 && (int)$ra['following_count'] === 0;
                    if (($age > 3600 || ($hasZeroCounts && $age > 60)) && !isset($queuedRefresh[$fromId])) {
                        $queuedRefresh[$fromId] = true;
                        // Never block notification rendering on remote profile refreshes.
                        // A single stale remote actor could otherwise add multiple network
                        // round-trips here and make the notifications screen feel hung.
                        defer_after_response(function () use ($fromId): void {
                            if (throttle_allow('remote_actor_refresh:' . $fromId, 1800)) {
                                RemoteActorModel::fetch($fromId, true);
                            }
                        });
                    }
                    $actorCache[$fromId] = $ra;
                } else {
                    $ra = $actorCache[$fromId];
                }
                $fromAcc = UserModel::remoteToMasto($ra);
            } elseif (str_starts_with($fromId, 'http')) {
                $ra = RemoteActorModel::fetch($fromId, true);
                if ($ra) {
                    $actorCache[$fromId] = $ra;
                    $fromAcc = UserModel::remoteToMasto($ra);
                }
            }
        }
        if (!$fromAcc) return null;

        $out = [
            'id'         => $n['id'],
            'type'       => $n['type'],
            'created_at' => iso_z($n['created_at']),
            'read_at'    => $n['read_at'] ? iso_z($n['read_at']) : null,
            'account'    => $fromAcc,
            // group_key is required (non-optional String) in Mastodon 4.3+ — official Mastodon iOS app
            // throws DecodingError.keyNotFound if this field is absent.
            'group_key'  => $this->groupKeyFor($n),
            'filtered'   => [],
        ];

        // Always include 'status' field — Ivory/Swift Codable requires key present even if null
        $statusTypes = ['mention', 'reblog', 'favourite', 'poll', 'update', 'status', 'direct'];
        $s = (in_array($n['type'], $statusTypes) && $n['status_id'])
            ? StatusModel::byId($n['status_id'])
            : null;
        $out['status'] = $s ? StatusModel::toMasto($s, $me['id']) : null;

        return $out;
    }

    public function shouldAppearInMainList(array $n, array $user): bool
    {
        return !$this->notificationRequiresRequest($n, $user['id'], $this->loadPolicy($user));
    }
}
