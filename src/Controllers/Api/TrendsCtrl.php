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

        if ($pathLower === '' || $pathLower === '/') return false;

        if (preg_match('~/(?:@[^/]+|users/[^/]+|profile/[^/]+|profiles/[^/]+|u/[^/]+|c/[^/]+|channel/[^/]+|people/[^/]+|author/[^/]+|member/[^/]+|members/[^/]+)$~i', $path)) {
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

    /** Build 7-day history for a set of hashtag IDs. Returns [hashtag_id => history_array]. */
    private static function tagHistoryBatch(array $ids): array
    {
        if (!$ids) return [];
        $ph    = implode(',', array_fill(0, count($ids), '?'));
        $since = gmdate('Y-m-d', strtotime('-7 days'));
        $blocked      = StatusModel::blockedDomains();
        $domainFilter = StatusModel::domainBlockSql('s.user_id', $blocked);
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
               $domainFilter
             GROUP BY sh.hashtag_id, day
             ORDER BY day DESC",
            array_merge($ids, [$since])
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

        $blocked      = StatusModel::blockedDomains();
        $domainFilter = StatusModel::domainBlockSql('s.user_id', $blocked);
        $reblogDomainFilter = StatusModel::domainBlockSql('r.user_id', $blocked);

        // score = (public_boosts×2 + favourite_count + 1) × EXP(-age_hours × ln2 / 4)
        // Compute boosts in a separate aggregate pass instead of LEFT JOIN-ing all recent
        // reblogs into every candidate row. On SQLite/shared hosting that join is the main
        // cost of this endpoint and quickly becomes the slowest public API query.
        $outerFilter = '';
        $since = gmdate('Y-m-d\TH:i:s\Z', strtotime('-2 days'));
        $params = [$since, $since];

        // Cursor paging must follow the same ordering as the endpoint: trend_score DESC, id DESC.
        // Filtering only by id is wrong here and can skip or repeat statuses with higher/lower scores.
        if ($maxId) {
            $ref = DB::one(
                "WITH candidates AS (
                    SELECT s.id, s.favourite_count, s.created_at
                    FROM statuses s
                    WHERE s.visibility = 'public'
                      AND s.reblog_of_id IS NULL
                      AND s.created_at > ?
                      {$domainFilter}
                 ),
                 public_reblogs AS (
                    SELECT r.reblog_of_id AS status_id, COUNT(*) AS public_boosts
                    FROM statuses r
                    WHERE r.visibility = 'public'
                      AND r.reblog_of_id IS NOT NULL
                      AND r.created_at > ?
                      {$reblogDomainFilter}
                    GROUP BY r.reblog_of_id
                 ),
                 scored AS (
                    SELECT c.id,
                           (COALESCE(pr.public_boosts, 0) * 2 + c.favourite_count + 1) * EXP(
                               -CAST((JULIANDAY('now') - JULIANDAY(c.created_at)) * 24.0 AS REAL)
                               * 0.693147 / 4.0
                           ) AS trend_score
                    FROM candidates c
                    LEFT JOIN public_reblogs pr ON pr.status_id = c.id
                 )
                 SELECT trend_score, id FROM scored WHERE id=? LIMIT 1",
                [$since, $since, $maxId]
            );
            if ($ref) {
                $outerFilter = ' WHERE (trend_score < ? OR (trend_score = ? AND id < ?))';
                $params[] = $ref['trend_score'];
                $params[] = $ref['trend_score'];
                $params[] = $ref['id'];
            }
        }
        $params[] = $limit;

        $sql = "
            WITH candidates AS (
                SELECT s.*
                FROM statuses s
                WHERE s.visibility = 'public'
                  AND s.reblog_of_id IS NULL
                  AND s.created_at > ?
                  {$domainFilter}
            ),
            public_reblogs AS (
                SELECT r.reblog_of_id AS status_id, COUNT(*) AS public_boosts
                FROM statuses r
                WHERE r.visibility = 'public'
                  AND r.reblog_of_id IS NOT NULL
                  AND r.created_at > ?
                  {$reblogDomainFilter}
                GROUP BY r.reblog_of_id
            ),
            scored AS (
                SELECT c.*,
                       (COALESCE(pr.public_boosts, 0) * 2 + c.favourite_count + 1) * EXP(
                           -CAST((JULIANDAY('now') - JULIANDAY(c.created_at)) * 24.0 AS REAL)
                           * 0.693147 / 4.0
                       ) AS trend_score
                FROM candidates c
                LEFT JOIN public_reblogs pr ON pr.status_id = c.id
            )
            SELECT * FROM scored
            {$outerFilter}
            ORDER BY trend_score DESC, id DESC
            LIMIT ?
        ";

        $rows = DB::all($sql, $params);
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
        $blocked      = StatusModel::blockedDomains();
        $domainFilter = StatusModel::domainBlockSql('s.user_id', $blocked);

        $rows = DB::all(
            "SELECT h.name, h.id,
                    COUNT(*) * EXP(
                        -CAST((JULIANDAY('now') - JULIANDAY(MAX(s.created_at))) * 24.0 AS REAL)
                        * 0.693147 / 4.0
                    ) AS trend_score
             FROM hashtags h
             JOIN status_hashtags sh ON sh.hashtag_id = h.id
             JOIN statuses s ON s.id = sh.status_id
             WHERE s.created_at > ? AND s.visibility = 'public'
               $domainFilter
             GROUP BY h.id
             HAVING COUNT(*) >= 1
             ORDER BY trend_score DESC, h.name ASC
             LIMIT ? OFFSET ?",
            [$since, $limit, $offset]
        );

        $ids     = array_column($rows, 'id');
        $history = self::tagHistoryBatch($ids);

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
            [$since, max($limit * 5, 50)]
        );

        $out = [];
        foreach ($rows as $r) {
            if (self::looksLikeProfileCard($r)) {
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
        $blocked = array_map('strtolower', StatusModel::blockedDomains());

        if ($uid) {
            $rows = DB::all(
                "SELECT f2.following_id AS account_id, COUNT(*) AS mutual_count
                 FROM follows f1
                 JOIN follows f2 ON f2.follower_id = f1.following_id AND f2.pending = 0
                 WHERE f1.follower_id = ? AND f1.pending = 0
                   AND f2.following_id != ?
                   AND f2.following_id NOT IN (
                       SELECT following_id FROM follows WHERE follower_id = ? AND pending = 0
                   )
                 GROUP BY f2.following_id
                 ORDER BY mutual_count DESC
                 LIMIT ?",
                [$uid, $uid, $uid, $limit * 3]
            );
        } else {
            $rows = [];
        }

        if (count($rows) < $limit) {
            $need       = $limit - count($rows);
            $alreadyIds = array_column($rows, 'account_id');

            $localSql    = "SELECT id AS account_id, 0 AS mutual_count FROM users WHERE is_suspended=0 AND is_bot=0 AND discoverable=1";
            $localParams = [];
            if ($uid) {
                $localSql .= ' AND id != ? AND id NOT IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)';
                $localParams[] = $uid;
                $localParams[] = $uid;
            }
            if ($alreadyIds) {
                $localSql .= ' AND id NOT IN (' . implode(',', array_fill(0, count($alreadyIds), '?')) . ')';
                array_push($localParams, ...$alreadyIds);
            }
            $localSql .= ' ORDER BY follower_count DESC LIMIT ?';
            $localParams[] = $need;
            $rows = array_merge($rows, DB::all($localSql, $localParams));

            if (count($rows) < $limit) {
                $need2       = $limit - count($rows);
                $alreadyIds2 = array_column($rows, 'account_id');
                $remoteSql   = 'SELECT id AS account_id, 0 AS mutual_count FROM remote_actors WHERE username != \'\' AND domain != \'\' AND is_bot=0';
                $remoteParams = [];
                if ($uid) {
                    $remoteSql .= ' AND id != ? AND id NOT IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)';
                    $remoteParams[] = $uid;
                    $remoteParams[] = $uid;
                }
                if ($blocked) {
                    $remoteSql .= ' AND LOWER(domain) NOT IN (' . implode(',', array_fill(0, count($blocked), '?')) . ')';
                    array_push($remoteParams, ...$blocked);
                }
                if ($alreadyIds2) {
                    $remoteSql .= ' AND id NOT IN (' . implode(',', array_fill(0, count($alreadyIds2), '?')) . ')';
                    array_push($remoteParams, ...$alreadyIds2);
                }
                $remoteSql .= ' ORDER BY follower_count DESC LIMIT ?';
                $remoteParams[] = $need2;
                $rows = array_merge($rows, DB::all($remoteSql, $remoteParams));
            }
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
