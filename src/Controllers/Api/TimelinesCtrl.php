<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, StatusModel, UserModel};

class TimelinesCtrl
{
    // Emite header Link: com next/prev para paginação (Mastodon-compatible).
    // Usa as rows cruas para evitar perder cursores quando a serialização filtra
    // a página inteira por visibilidade/expiração.
    private function paginationLinks(array $rows, string $baseUrl, array $query = [], bool $ascending = false): void
    {
        if (!$rows) return;
        $oldest = $ascending ? reset($rows) : end($rows);
        $newest = $ascending ? end($rows) : reset($rows);

        $nextParams = http_build_query(array_merge($query, ['max_id' => $oldest['id']]));
        $prevParams = http_build_query(array_merge($query, ['min_id' => $newest['id']]));

        $linkValue = sprintf(
            '<%s?%s>; rel="next", <%s?%s>; rel="prev"',
            $baseUrl, $nextParams,
            $baseUrl, $prevParams
        );

        header('Link: ' . $linkValue);
        // Fallback: alguns proxies/CDN removem o header Link — emitir também como X-Link
        header('X-Link: ' . $linkValue);
    }

    public function home(array $p): void
    {
        $user    = require_auth('read');
        $limit   = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;
        $rows = StatusModel::homeTimeline($user['id'], $limit, $maxId, $sinceId, $minId);
        $out  = array_values(array_filter(array_map(
            fn($s) => StatusModel::toMasto($s, $user['id']),
            $rows
        )));
        // min_id returns ASC from DB (to get the gap); reverse to newest-first before sending
        if ($minId && $out) $out = array_reverse($out);
        if ($rows) {
            $this->paginationLinks(
                $rows,
                ap_url('api/v1/timelines/home'),
                array_filter(['limit' => $limit]),
                (bool)$minId
            );
        }
        json_out($out);
    }

    public function public(array $p): void
    {
        $viewer  = authed_user();
        $limit   = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;
        $localOnly = filter_var($_GET['local'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $remoteOnly = !$localOnly && filter_var($_GET['remote'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $onlyMedia = filter_var($_GET['only_media'] ?? false, FILTER_VALIDATE_BOOLEAN)
            || filter_var($_GET['media_only'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $rows = StatusModel::publicTimeline($limit, $maxId, $sinceId, $viewer['id'] ?? null, $minId, $localOnly, $remoteOnly, $onlyMedia);
        $out  = array_values(array_filter(array_map(
            fn($s) => StatusModel::toMasto($s, $viewer['id'] ?? null),
            $rows
        )));
        if ($minId && $out) $out = array_reverse($out);
        if ($rows) {
            $this->paginationLinks(
                $rows,
                ap_url('api/v1/timelines/public'),
                array_filter(['limit' => $limit, 'local' => $localOnly ? 'true' : null, 'remote' => $remoteOnly ? 'true' : null, 'only_media' => $onlyMedia ? 'true' : null]),
                (bool)$minId
            );
        }
        json_out($out);
    }

    public function tag(array $p): void
    {
        $viewer  = authed_user();
        $tag     = mb_strtolower((string)$p['hashtag'], 'UTF-8');
        $limit   = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;

        $blocked      = StatusModel::blockedDomains($viewer['id'] ?? null);
        $domainFilter = StatusModel::domainBlockSql('s.user_id', $blocked);

        $sql = "SELECT s.* FROM statuses s
                JOIN status_hashtags sh ON sh.status_id=s.id
                JOIN hashtags h ON h.id=sh.hashtag_id
                WHERE h.name=? AND s.visibility='public'
                  AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
                  AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
                  {$domainFilter}";
        $par = [$tag, now_iso()];
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$maxId]);
            if (!$ref && ctype_digit($maxId)) {
                $ms  = ((int)$maxId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $maxId];
            }
            if ($ref) { $sql .= ' AND (s.created_at < ? OR (s.created_at = ? AND s.id < ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($sinceId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$sinceId]);
            if (!$ref && ctype_digit($sinceId)) {
                $ms  = ((int)$sinceId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $sinceId];
            }
            if ($ref) { $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($minId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$minId]);
            if (!$ref && ctype_digit($minId)) {
                $ms  = ((int)$minId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $minId];
            }
            if ($ref) { $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($minId) {
            $sql .= ' ORDER BY s.created_at ASC, s.id ASC LIMIT ?';
        } else {
            $sql .= ' ORDER BY s.created_at DESC, s.id DESC LIMIT ?';
        }
        $par[] = $limit;

        $rows = DB::all($sql, $par);
        $out  = array_values(array_filter(array_map(
            fn($s) => StatusModel::toMasto($s, $viewer['id'] ?? null),
            $rows
        )));
        if ($minId && $out) $out = array_reverse($out);
        if ($rows) {
            $this->paginationLinks(
                $rows,
                ap_url('api/v1/timelines/tag/' . rawurlencode($tag)),
                array_filter(['limit' => $limit]),
                (bool)$minId
            );
        }
        json_out($out);
    }

    public function listTimeline(array $p): void
    {
        $user  = require_auth('read');
        $list  = DB::one('SELECT * FROM lists WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$list) err_out('Not found', 404);

        $limit   = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;

        $acctIds = array_column(
            DB::all('SELECT account_id FROM list_accounts WHERE list_id=?', [$p['id']]),
            'account_id'
        );
        if (!$acctIds) { json_out([]); return; }

        $blockedDomains = StatusModel::blockedDomains($user['id']);
        $domainFilter   = StatusModel::domainBlockSql('user_id', $blockedDomains);

        $phs = implode(',', array_fill(0, count($acctIds), '?'));
        $sql = "SELECT * FROM statuses WHERE user_id IN ($phs)"
             . " AND (visibility IN ('public','unlisted') OR (visibility='private' AND user_id IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)))"
             . " AND (expires_at IS NULL OR expires_at='' OR expires_at>?)"
             . " AND (user_id LIKE 'http%' OR user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))"
             . " AND user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)"
             . " AND user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)"
             . $domainFilter;
        $par = array_merge($acctIds, [$user['id'], now_iso(), $user['id'], $user['id']]);
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$maxId]);
            if (!$ref && ctype_digit($maxId)) {
                $ms  = ((int)$maxId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $maxId];
            }
            if ($ref) { $sql .= ' AND (created_at < ? OR (created_at = ? AND id < ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($sinceId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$sinceId]);
            if (!$ref && ctype_digit($sinceId)) {
                $ms  = ((int)$sinceId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $sinceId];
            }
            if ($ref) { $sql .= ' AND (created_at > ? OR (created_at = ? AND id > ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($minId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$minId]);
            if (!$ref && ctype_digit($minId)) {
                $ms  = ((int)$minId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $minId];
            }
            if ($ref) {
                $sql .= ' AND (created_at > ? OR (created_at = ? AND id > ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        $sql .= $minId ? ' ORDER BY created_at ASC, id ASC LIMIT ?' : ' ORDER BY created_at DESC, id DESC LIMIT ?';
        $par[] = $limit;

        $rows = DB::all($sql, $par);
        $out  = array_values(array_filter(array_map(
            fn($s) => StatusModel::toMasto($s, $user['id']),
            $rows
        )));
        if ($minId && $out) $out = array_reverse($out);
        if ($rows) {
            $this->paginationLinks(
                $rows,
                ap_url('api/v1/timelines/list/' . $p['id']),
                array_filter(['limit' => $limit]),
                (bool)$minId
            );
        }
        json_out($out);
    }
}
