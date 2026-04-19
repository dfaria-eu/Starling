<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, StatusModel, UserModel};

class TrendsCtrl
{
    private static function looksLikeProfileUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!$parts) return false;

        $host = strtolower((string)($parts['host'] ?? ''));
        $path = rawurldecode((string)($parts['path'] ?? ''));
        $path = preg_replace('~/+~', '/', $path ?? '') ?? '';
        $pathLower = strtolower($path);
        $query = (string)($parts['query'] ?? '');

        $socialHosts = [
            'mastodon.social', 'bsky.app', 'twitter.com', 'x.com', 'instagram.com',
            'facebook.com', 'www.facebook.com', 'linkedin.com', 'www.linkedin.com',
            'youtube.com', 'www.youtube.com', 'tiktok.com', 'www.tiktok.com',
            'threads.net', 'www.threads.net',
        ];
        foreach ($socialHosts as $socialHost) {
            if ($host === $socialHost || str_ends_with($host, '.' . $socialHost)) {
                return true;
            }
        }

        if ($query !== '' && ($pathLower === '' || $pathLower === '/')) {
            parse_str($query, $queryParams);
            foreach (['author', 'author_name', 'profile', 'username', 'acct', 'handle'] as $key) {
                $value = $queryParams[$key] ?? null;
                if (is_string($value) && trim($value) !== '') {
                    return true;
                }
            }
        }

        if ($pathLower === '' || $pathLower === '/') return false;

        if (preg_match('~/(?:@[^/]+|user/[^/]+|users/[^/]+|profile/[^/]+|profiles/[^/]+|u/[^/]+|c/[^/]+|channel/[^/]+|people/[^/]+|author/[^/]+|member/[^/]+|members/[^/]+)$~i', $path)) {
            return true;
        }

        return false;
    }

    private static function looksLikeProfileCard(array $row): bool
    {
        $title = trim((string)($row['title'] ?? ''));
        $description = trim((string)($row['description'] ?? ''));
        $provider = trim((string)($row['provider'] ?? ''));

        if (self::looksLikeProfileUrl((string)($row['url'] ?? ''))) {
            return true;
        }

        if ($provider !== '' && preg_match('~\b(?:mastodon|bluesky|twitter|x|instagram|facebook|linkedin|youtube|tiktok|threads)\b~i', $provider)) {
            return true;
        }

        if ($title !== '' && preg_match('~^@[\p{L}\p{N}._-]+(?:\s*\(|\s*$)~u', $title)) {
            return true;
        }

        if ($description !== '' && preg_match('~\b(?:followers?|following|joined|posts?|publicações|seguidores|seguidos)\b~iu', $description)) {
            return true;
        }

        return false;
    }

    private static function looksGenericNewsUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!$parts) return false;

        $path = rawurldecode((string)($parts['path'] ?? ''));
        $path = preg_replace('~/+~', '/', $path ?? '') ?? '';
        $pathLower = strtolower($path);

        if ($pathLower === '' || $pathLower === '/') {
            return true;
        }

        if (preg_match('~^/(?:tag|tags|category|categories|topic|topics|search|discover|explore|latest|recent|archive|archives|feed|feeds)(?:/|$)~i', $pathLower)) {
            return true;
        }

        return false;
    }

    private static function registrableDomain(string $url): string
    {
        $host = strtolower((string)(parse_url($url, PHP_URL_HOST) ?? ''));
        if ($host === '') return '';
        if (str_starts_with($host, 'www.')) $host = substr($host, 4);
        return $host;
    }

    private static function looksLikeLowQualityNewsCard(array $row): bool
    {
        $url = trim((string)($row['url'] ?? ''));
        $title = trim((string)($row['title'] ?? ''));
        $description = trim((string)($row['description'] ?? ''));
        $provider = trim((string)($row['provider'] ?? ''));
        $image = trim((string)($row['image'] ?? ''));
        $host = self::registrableDomain($url);
        $path = strtolower(rawurldecode((string)(parse_url($url, PHP_URL_PATH) ?? '')));

        if ($url === '' || $title === '') return true;

        if (preg_match('~^(?:just a moment|redirecting|301 moved permanently|302 found|403 forbidden|404 not found|access denied|handle redirect|error)$~iu', $title)) {
            return true;
        }

        if (preg_match('~\b(?:donate|donation|fundrais|contribute|chip in|petition|sign up)\b~iu', $title . ' ' . $description . ' ' . $provider)) {
            return true;
        }

        if ($host !== '' && preg_match('~(?:^|\.)bsky\.brid\.gy$~i', $host)) {
            return true;
        }

        if (preg_match('~/(?:ap|users|profile|profiles|@[^/]+)(?:/|$)~i', $path) && self::looksLikeProfileUrl($url)) {
            return true;
        }

        if ($description === '' && $image === '' && $provider === '') {
            return true;
        }

        return false;
    }

    private static function newsTrendScore(array $row): float
    {
        $shareCount = max(0, (int)($row['share_count'] ?? 0));
        $fetchedAt = strtotime((string)($row['fetched_at'] ?? '')) ?: time();
        $ageHours = max(0.0, (time() - $fetchedAt) / 3600.0);
        $baseScore = log($shareCount + 1) * exp(-$ageHours * 0.693147 / 8.0);

        $url = trim((string)($row['url'] ?? ''));
        $title = trim((string)($row['title'] ?? ''));
        $description = trim((string)($row['description'] ?? ''));
        $provider = trim((string)($row['provider'] ?? ''));
        $titleWords = preg_match_all('~[\p{L}\p{N}]+~u', $title);
        $descWords = preg_match_all('~[\p{L}\p{N}]+~u', $description);
        $parts = parse_url($url) ?: [];
        $path = rawurldecode((string)($parts['path'] ?? ''));
        $path = preg_replace('~/+~', '/', $path ?? '') ?? '';
        $pathLower = strtolower($path);
        $segments = array_values(array_filter(explode('/', trim($pathLower, '/')), fn($s) => $s !== ''));

        $multiplier = 1.0;

        if (self::looksGenericNewsUrl($url)) {
            $multiplier *= 0.2;
        }

        if (count($segments) >= 2) {
            $multiplier *= 1.15;
        }

        if (preg_match('~/(?:news|article|articles|post|posts|blog)/~i', $pathLower) || preg_match('~/(?:19|20)\d{2}/(?:0[1-9]|1[0-2])(?:/\d{1,2})?/~', $pathLower)) {
            $multiplier *= 1.2;
        }

        if ($titleWords >= 4) {
            $multiplier *= 1.08;
        }

        if ($descWords >= 12) {
            $multiplier *= 1.12;
        }

        if ($provider !== '' && mb_strtolower($title) === mb_strtolower($provider)) {
            $multiplier *= 0.75;
        }

        if ($description === '') {
            $multiplier *= 0.75;
        }

        if (trim((string)($row['image'] ?? '')) === '') {
            $multiplier *= 0.9;
        }

        return $baseScore * $multiplier;
    }

    private static function suggestionHash(string $accountId, ?string $viewerId): int
    {
        $seed = gmdate('Y-m-d') . '|' . ($viewerId ?? 'anon') . '|' . $accountId;
        return (int)sprintf('%u', crc32($seed));
    }

    /** Keep the strongest anchors, then rotate within small windows for variety. */
    private static function pickInterestingFallbackPeople(array $rows, int $need, ?string $viewerId): array
    {
        if ($need <= 0) return [];
        if (count($rows) <= $need) return array_slice($rows, 0, $need);

        $anchors = array_slice($rows, 0, min(2, $need));
        $pool = array_slice($rows, count($anchors));
        $windowSize = 6;
        $picked = $anchors;

        foreach (array_chunk($pool, $windowSize) as $chunk) {
            usort($chunk, function (array $a, array $b) use ($viewerId): int {
                return self::suggestionHash((string)$a['account_id'], $viewerId)
                    <=> self::suggestionHash((string)$b['account_id'], $viewerId);
            });
            foreach ($chunk as $row) {
                $picked[] = $row;
                if (count($picked) >= $need) {
                    return $picked;
                }
            }
        }

        return array_slice($picked, 0, $need);
    }

    /** Build 7-day history for a set of hashtag IDs. Returns [hashtag_id => history_array]. */
    private static function tagHistoryBatch(array $ids, array $blockedDomains = []): array
    {
        if (!$ids) return [];
        $ph    = implode(',', array_fill(0, count($ids), '?'));
        $since = gmdate('Y-m-d', strtotime('-7 days'));
        $domainFilter = StatusModel::domainBlockSql('s.user_id', $blockedDomains);
        $rows  = DB::all(
            "SELECT sh.hashtag_id,
                    CAST(strftime('%s', date(s.created_at)) AS TEXT) AS day,
                    COUNT(*)                                          AS uses,
                    COUNT(DISTINCT s.user_id)                        AS accounts
             FROM status_hashtags sh
             JOIN statuses s ON s.id = sh.status_id
             WHERE sh.hashtag_id IN ($ph)
               AND date(s.created_at) >= ?
               AND s.visibility = 'public'
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
               AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
               $domainFilter
             GROUP BY sh.hashtag_id, day
             ORDER BY day DESC",
            array_merge($ids, [$since, now_iso()])
        );

        $map = array_fill_keys($ids, []);
        foreach ($rows as $r) {
            $map[$r['hashtag_id']][] = [
                'day'      => $r['day'],
                'uses'     => (string)$r['uses'],
                'accounts' => (string)$r['accounts'],
            ];
        }
        return $map;
    }

    public function statuses(array $p): void
    {
        $viewer = authed_user();
        $limit  = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $maxId  = $_GET['max_id'] ?? null;

        $blocked      = StatusModel::blockedDomains($viewer['id'] ?? null);
        $domainFilter = StatusModel::domainBlockSql('s.user_id', $blocked);
        $reblogDomainFilter = StatusModel::domainBlockSql('r.user_id', $blocked);

        // score = (public_boosts×2 + favourite_count + reply_count×0.25 + 1) × EXP(-age_hours × ln2 / 5)
        // Compute boosts in a separate aggregate pass instead of LEFT JOIN-ing all recent
        // reblogs into every candidate row. On SQLite/shared hosting that join is the main
        // cost of this endpoint and quickly becomes the slowest public API query.
        $since = gmdate('Y-m-d\TH:i:s\Z', strtotime('-2 days'));
        $poolLimit = max($limit * 8, 200);
        $params = [$since, now_iso(), $since, now_iso(), $poolLimit];

        $sql = "
            WITH candidates AS (
                SELECT s.*
                FROM statuses s
                WHERE s.visibility = 'public'
                  AND s.reblog_of_id IS NULL
                  AND s.created_at > ?
                  AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
                  AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
                  {$domainFilter}
            ),
            public_reblogs AS (
                SELECT r.reblog_of_id AS status_id, COUNT(*) AS public_boosts
                FROM statuses r
                WHERE r.visibility = 'public'
                  AND r.reblog_of_id IS NOT NULL
                  AND r.created_at > ?
                  AND (r.expires_at IS NULL OR r.expires_at='' OR r.expires_at>?)
                  AND (r.user_id LIKE 'http%' OR r.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
                  {$reblogDomainFilter}
                GROUP BY r.reblog_of_id
            ),
            scored AS (
                SELECT c.*,
                       (COALESCE(pr.public_boosts, 0) * 2 + c.favourite_count + (c.reply_count * 0.25) + 1) * EXP(
                           -CAST((JULIANDAY('now') - JULIANDAY(c.created_at)) * 24.0 AS REAL)
                           * 0.693147 / 5.0
                       ) AS trend_score
                FROM candidates c
                LEFT JOIN public_reblogs pr ON pr.status_id = c.id
            )
            SELECT * FROM scored
            ORDER BY trend_score DESC, id DESC
            LIMIT ?
        ";

        $rows = DB::all($sql, $params);
        if ($maxId !== null && $maxId !== '') {
            $cursorIndex = null;
            foreach ($rows as $index => $row) {
                if ((string)($row['id'] ?? '') === (string)$maxId) {
                    $cursorIndex = $index;
                    break;
                }
            }
            $rows = $cursorIndex === null ? [] : array_slice($rows, $cursorIndex + 1, $limit);
        } else {
            $rows = array_slice($rows, 0, $limit);
        }
        $out  = array_values(array_filter(array_map(
            fn($s) => StatusModel::toMasto($s, $viewer['id'] ?? null),
            $rows
        )));
        json_out($out);
    }

    public function tags(array $p): void
    {
        $limit  = max(1, min((int)($_GET['limit'] ?? 10), 20));
        $offset = max(0, (int)($_GET['offset'] ?? 0));
        $since  = gmdate('Y-m-d\TH:i:s\Z', strtotime('-2 days'));
        $viewer = authed_user();
        $userId = $viewer['id'] ?? null;
        $blocked      = StatusModel::blockedDomains($userId);
        $domainFilter = StatusModel::domainBlockSql('s.user_id', $blocked);

        $rows = DB::all(
            "SELECT h.name, h.id,
                    (
                        COUNT(DISTINCT s.user_id) * 3
                        + COUNT(*) * 0.5
                        + 1
                    ) * EXP(
                        -CAST((JULIANDAY('now') - JULIANDAY(MAX(s.created_at))) * 24.0 AS REAL)
                        * 0.693147 / 6.0
                    ) AS trend_score
             FROM hashtags h
             JOIN status_hashtags sh ON sh.hashtag_id = h.id
             JOIN statuses s ON s.id = sh.status_id
             WHERE s.created_at > ? AND s.visibility = 'public'
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
               AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
               $domainFilter
             GROUP BY h.id
             HAVING COUNT(*) >= 1
             ORDER BY trend_score DESC, h.name ASC
             LIMIT ? OFFSET ?",
            [$since, now_iso(), $limit, $offset]
        );

        $ids     = array_column($rows, 'id');
        $history = self::tagHistoryBatch($ids, $blocked);

        json_out(array_map(function ($r) use ($userId, $history) {
            $following = $userId
                ? (bool)DB::one('SELECT 1 FROM tag_follows WHERE user_id=? AND hashtag_id=?', [$userId, $r['id']])
                : false;
            return [
                'id'        => $r['id'],
                'name'      => $r['name'],
                'url'       => ap_url('tags/' . rawurlencode($r['name'])),
                'history'   => $history[$r['id']] ?? [],
                'following' => $following,
            ];
        }, $rows));
    }

    public function links(array $p): void
    {
        $limit = max(1, min((int)($_GET['limit'] ?? 10), 20));
        $since = gmdate('Y-m-d\TH:i:s\Z', strtotime('-7 days'));
        $rows  = DB::all(
            "SELECT
                MIN(url)              AS url,
                title,
                description,
                provider,
                image,
                COALESCE(card_type, 'link') AS card_type,
                MAX(share_count)      AS share_count,
                MAX(fetched_at)       AS fetched_at
             FROM link_cards
             WHERE title != '' AND fetched_at > ? AND share_count > 0
               AND title NOT LIKE '%<%'
               AND description NOT LIKE '%<meta%'
               AND description NOT LIKE '%<link%'
               AND provider NOT LIKE '%<%'
               AND image NOT LIKE '%<%'
             GROUP BY title, description, provider, image, COALESCE(card_type, 'link')
             ORDER BY (MAX(share_count) + 1) * EXP(
                 -CAST((JULIANDAY('now') - JULIANDAY(MAX(fetched_at))) * 24.0 AS REAL)
                 * 0.693147 / 8.0
             ) DESC, fetched_at DESC
             LIMIT ?",
            [$since, max($limit * 8, 80)]
        );

        $scored = [];
        foreach ($rows as $r) {
            if (self::looksLikeProfileCard($r)) {
                continue;
            }
            if (self::looksGenericNewsUrl((string)($r['url'] ?? ''))) {
                continue;
            }
            if (self::looksLikeLowQualityNewsCard($r)) {
                continue;
            }
            $r['_news_score'] = self::newsTrendScore($r);
            $scored[] = $r;
        }

        usort($scored, static function (array $a, array $b): int {
            $scoreCmp = (($b['_news_score'] ?? 0.0) <=> ($a['_news_score'] ?? 0.0));
            if ($scoreCmp !== 0) return $scoreCmp;
            return strcmp((string)($b['fetched_at'] ?? ''), (string)($a['fetched_at'] ?? ''));
        });

        $out = [];
        $domainCounts = [];
        foreach ($scored as $r) {
            $domain = self::registrableDomain((string)($r['url'] ?? ''));
            $domainCounts[$domain] = ($domainCounts[$domain] ?? 0) + 1;
            if ($domain !== '' && $domainCounts[$domain] > 3) {
                continue;
            }

            $out[] = [
                'url'               => $r['url'],
                'title'             => $r['title'],
                'description'       => $r['description'],
                'type'              => $r['card_type'] ?? 'link',
                'author_name'       => '',
                'author_url'        => '',
                'provider_name'     => $r['provider'],
                'provider_url'      => '',
                'html'              => '',
                'width'             => 0,
                'height'            => 0,
                'image'             => (($r['image'] ?? '') !== '' ? (absolute_url($r['url'] ?? '', (string)$r['image']) ?: null) : null),
                'image_description' => '',
                'embed_url'         => '',
                'blurhash'          => null,
                'history'           => [[
                    'day'      => (string)strtotime(gmdate('Y-m-d', strtotime($r['fetched_at']))),
                    'accounts' => '1',
                    'uses'     => (string)max(0, (int)($r['share_count'] ?? 0)),
                ]],
                'authors'           => [],
            ];
            if (count($out) >= $limit) {
                break;
            }
        }
        json_out($out);
    }

    public function people(array $p): void
    {
        $viewer = authed_user();
        $uid    = $viewer['id'] ?? null;
        $limit  = max(1, min((int)($_GET['limit'] ?? 5), 20));
        $blocked = StatusModel::blockedDomains($uid);

        if ($uid) {
            $rows = DB::all(
                "SELECT f2.following_id AS account_id, COUNT(*) AS mutual_count
                 FROM follows f1
                 JOIN follows f2 ON f2.follower_id = f1.following_id AND f2.pending = 0
                 WHERE f1.follower_id = ? AND f1.pending = 0
                   AND f2.following_id != ?
                   AND f2.following_id NOT IN (SELECT target_id FROM blocks WHERE user_id = ?)
                   AND f2.following_id NOT IN (SELECT target_id FROM mutes WHERE user_id = ?)
                   AND f2.following_id NOT IN (
                       SELECT following_id FROM follows WHERE follower_id = ? AND pending = 0
                   )
                 GROUP BY f2.following_id
                 ORDER BY mutual_count DESC
                 LIMIT ?",
                [$uid, $uid, $uid, $uid, $uid, $limit * 3]
            );
        } else {
            $rows = [];
        }

        if (count($rows) < $limit) {
            $need       = $limit - count($rows);
            $alreadyIds = array_column($rows, 'account_id');
            $recentSince = gmdate('Y-m-d\TH:i:s\Z', strtotime('-14 days'));
            $fallbackRows = [];

            $localSql    = "SELECT
                                u.id AS account_id,
                                0 AS mutual_count,
                                u.follower_count AS follower_count,
                                COALESCE(rs.recent_posts, 0) AS recent_posts,
                                COALESCE(rs.last_post_at, '') AS last_post_at
                            FROM users u
                            LEFT JOIN (
                                SELECT user_id, COUNT(*) AS recent_posts, MAX(created_at) AS last_post_at
                                FROM statuses
                                WHERE visibility = 'public'
                                  AND reblog_of_id IS NULL
                                  AND created_at > ?
                                  AND (expires_at IS NULL OR expires_at='' OR expires_at>?)
                                  AND (user_id LIKE 'http%' OR user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
                                GROUP BY user_id
                            ) rs ON rs.user_id = u.id
                            WHERE u.is_suspended=0 AND u.is_bot=0 AND u.discoverable=1";
            $localParams = [$recentSince, now_iso()];
            if ($uid) {
                $localSql .= ' AND u.id != ? AND u.id NOT IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)';
                $localSql .= ' AND u.id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)';
                $localSql .= ' AND u.id NOT IN (SELECT target_id FROM mutes WHERE user_id=?)';
                $localParams[] = $uid;
                $localParams[] = $uid;
                $localParams[] = $uid;
                $localParams[] = $uid;
            }
            if ($alreadyIds) {
                $localSql .= ' AND u.id NOT IN (' . implode(',', array_fill(0, count($alreadyIds), '?')) . ')';
                array_push($localParams, ...$alreadyIds);
            }
            $localSql .= ' ORDER BY (CASE WHEN COALESCE(rs.recent_posts, 0) > 0 THEN 1 ELSE 0 END) DESC, COALESCE(rs.recent_posts, 0) DESC, u.follower_count DESC, u.id ASC LIMIT ?';
            $localParams[] = max($need * 6, 24);
            $fallbackRows = array_merge($fallbackRows, DB::all($localSql, $localParams));

            if (count($fallbackRows) < $need) {
                $need2       = $need - count($fallbackRows);
                $alreadyIds2 = array_merge($alreadyIds, array_column($fallbackRows, 'account_id'));
                $remoteSql   = "SELECT
                                    ra.id AS account_id,
                                    0 AS mutual_count,
                                    ra.follower_count AS follower_count,
                                    COALESCE(rs.recent_posts, 0) AS recent_posts,
                                    COALESCE(rs.last_post_at, '') AS last_post_at
                                FROM remote_actors ra
                                LEFT JOIN (
                                    SELECT user_id, COUNT(*) AS recent_posts, MAX(created_at) AS last_post_at
                                    FROM statuses
                                    WHERE visibility = 'public'
                                      AND reblog_of_id IS NULL
                                      AND created_at > ?
                                      AND (expires_at IS NULL OR expires_at='' OR expires_at>?)
                                      AND user_id LIKE 'http%'
                                    GROUP BY user_id
                                ) rs ON rs.user_id = ra.id
                                WHERE ra.username != '' AND ra.domain != '' AND ra.is_bot=0";
                $remoteParams = [$recentSince, now_iso()];
                if ($uid) {
                    $remoteSql .= ' AND ra.id != ? AND ra.id NOT IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)';
                    $remoteParams[] = $uid;
                    $remoteParams[] = $uid;
                    $remoteSql .= ' AND ra.id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)';
                    $remoteSql .= ' AND ra.id NOT IN (SELECT target_id FROM mutes WHERE user_id=?)';
                    $remoteParams[] = $uid;
                    $remoteParams[] = $uid;
                }
                if ($blocked) {
                    $remoteSql .= ' AND LOWER(ra.domain) NOT IN (' . implode(',', array_fill(0, count($blocked), '?')) . ')';
                    array_push($remoteParams, ...$blocked);
                }
                if ($alreadyIds2) {
                    $remoteSql .= ' AND ra.id NOT IN (' . implode(',', array_fill(0, count($alreadyIds2), '?')) . ')';
                    array_push($remoteParams, ...$alreadyIds2);
                }
                $remoteSql .= ' ORDER BY (CASE WHEN COALESCE(rs.recent_posts, 0) > 0 THEN 1 ELSE 0 END) DESC, COALESCE(rs.recent_posts, 0) DESC, ra.follower_count DESC, ra.id ASC LIMIT ?';
                $remoteParams[] = max($need2 * 6, 24);
                $fallbackRows = array_merge($fallbackRows, DB::all($remoteSql, $remoteParams));
            }

            $rows = array_merge($rows, self::pickInterestingFallbackPeople($fallbackRows, $need, $uid));
        }

        $accountIds = array_slice(array_column($rows, 'account_id'), 0, $limit);
        if (!$accountIds) {
            json_out([]);
            return;
        }

        $ph      = implode(',', array_fill(0, count($accountIds), '?'));
        $locals  = DB::all("SELECT * FROM users WHERE id IN ($ph)", $accountIds);
        $remotes = DB::all("SELECT * FROM remote_actors WHERE id IN ($ph)", $accountIds);

        $byId = [];
        foreach ($locals as $u) {
            $byId[$u['id']] = UserModel::toMasto($u, $uid);
        }
        foreach ($remotes as $r) {
            $byId[$r['id']] = UserModel::remoteToMasto($r);
        }

        $out = [];
        foreach ($accountIds as $id) {
            if ($uid) {
                $hidden = DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$uid, $id])
                    || DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$uid, $id]);
                if ($hidden) {
                    continue;
                }
            }
            $local = DB::one('SELECT is_suspended, is_bot, discoverable FROM users WHERE id=?', [$id]);
            if ($local) {
                if ((int)$local['is_suspended'] !== 0 || (int)$local['is_bot'] !== 0 || (int)$local['discoverable'] === 0) {
                    continue;
                }
            } else {
                $remote = DB::one('SELECT domain, is_bot FROM remote_actors WHERE id=?', [$id]);
                if ($remote) {
                    if ((int)$remote['is_bot'] !== 0 || in_array(strtolower($remote['domain'] ?? ''), $blocked, true)) {
                        continue;
                    }
                }
            }
            if (isset($byId[$id])) $out[] = $byId[$id];
            if (count($out) >= $limit) break;
        }
        json_out($out);
    }
}
