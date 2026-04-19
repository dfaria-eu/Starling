<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, StatusModel, MediaModel, RemoteActorModel};
use App\ActivityPub\{Builder, Delivery};

// ── Search ───────────────────────────────────────────────────

class SearchCtrl
{
    public function index(array $p): void
    {
        $q      = trim($_GET['q'] ?? '');
        $viewer = authed_user();
        $vid    = $viewer['id'] ?? null;
        $type   = strtolower(trim((string)($_GET['type'] ?? '')));
        $limit  = max(1, min((int)($_GET['limit'] ?? 5), 40));
        $resolve = bool_val($_GET['resolve'] ?? false);

        if (!$q) { json_out(['accounts' => [], 'statuses' => [], 'hashtags' => []]); return; }

        $accounts = [];
        $statuses = [];
        $hashtags = [];
        $wantAccounts = $type === '' || $type === 'accounts';
        $wantStatuses = $type === '' || $type === 'statuses';
        $wantHashtags = $type === '' || $type === 'hashtags';
        $blockedDomains = StatusModel::blockedDomains($vid);
        $isHiddenAccount = static function (string $targetId, ?string $domain = null) use ($vid, $blockedDomains): bool {
            if (!$vid) return false;
            if (DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$vid, $targetId])) return true;
            if (DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$vid, $targetId])) return true;
            return $domain !== null && in_array(strtolower($domain), $blockedDomains, true);
        };
        $isHiddenStatus = static function (array $s) use ($isHiddenAccount): bool {
            $userId = (string)($s['user_id'] ?? '');
            if ($userId === '') return false;
            $domain = null;
            if (str_starts_with($userId, 'http://') || str_starts_with($userId, 'https://')) {
                $domain = parse_url($userId, PHP_URL_HOST) ?: null;
            }
            return $isHiddenAccount($userId, $domain ?: null);
        };

        // ── Accounts ─────────────────────────────────────────
        $qLike = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';
        if ($wantAccounts) {
            // If query looks like @user@domain, resolve it directly.
            if (preg_match('/^([A-Za-z0-9_][A-Za-z0-9_.-]*)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$/', ltrim($q, '@'), $m)) {
                $username = $m[1];
                $domain   = strtolower($m[2]);
                if (is_local($domain)) {
                    $u = UserModel::byUsername($username);
                    if ($u) {
                        $hidden = $vid && (
                            DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$vid, $u['id']])
                            || DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$vid, $u['id']])
                        );
                        if (!$hidden) $accounts[] = UserModel::toMasto($u);
                    }
                } else {
                    $ra = DB::one('SELECT * FROM remote_actors WHERE LOWER(username)=? AND domain=?', [strtolower($username), $domain]);
                    if (!$ra && $resolve) {
                        $ra = RemoteActorModel::fetchByAcct($username, $domain);
                    }
                    if ($ra) {
                        $hidden = $vid && (
                            DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$vid, $ra['id']])
                            || DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$vid, $ra['id']])
                            || in_array(strtolower((string)($ra['domain'] ?? '')), $blockedDomains, true)
                        );
                        if (!$hidden) $accounts[] = UserModel::remoteToMasto($ra);
                    }
                }
            }

            $localSql = "SELECT * FROM users WHERE (username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\') AND is_suspended=0";
            $localParams = [$qLike, $qLike];
            if ($vid) {
                $localSql .= ' AND id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)';
                $localSql .= ' AND id NOT IN (SELECT target_id FROM mutes WHERE user_id=?)';
                $localParams[] = $vid;
                $localParams[] = $vid;
            }
            $localSql .= ' LIMIT ?';
            $localParams[] = $limit;
            $local = DB::all($localSql, $localParams);
            foreach ($local as $u) $accounts[] = UserModel::toMasto($u);

            $remoteSql = "SELECT * FROM remote_actors
                 WHERE domain != ?
                   AND (username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\')";
            $remoteParams = [AP_DOMAIN, $qLike, $qLike];
            if ($vid) {
                $remoteSql .= ' AND id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)';
                $remoteSql .= ' AND id NOT IN (SELECT target_id FROM mutes WHERE user_id=?)';
                $remoteParams[] = $vid;
                $remoteParams[] = $vid;
            }
            if ($blockedDomains) {
                $remoteSql .= ' AND LOWER(domain) NOT IN (' . implode(',', array_fill(0, count($blockedDomains), '?')) . ')';
                array_push($remoteParams, ...$blockedDomains);
            }
            $remoteSql .= ' LIMIT ?';
            $remoteParams[] = $limit;
            $remote = DB::all($remoteSql, $remoteParams);
            foreach ($remote as $ra) $accounts[] = UserModel::remoteToMasto($ra);
        }

        // ── Statuses ─────────────────────────────────────────
        // If the query looks like a URL, resolve it as a status URI first.
        // This is used by clients (Ivory, etc.) to resolve a remote post URL
        // before quoting it (GET /api/v2/search?q=URL&resolve=true).
        if ($wantStatuses && (str_starts_with($q, 'https://') || str_starts_with($q, 'http://'))) {
            $byUri = StatusModel::byUri($q);
            $queryHost = strtolower((string)(parse_url($q, PHP_URL_HOST) ?? ''));
            if (!$byUri && $resolve && !is_local($queryHost) && !in_array($queryHost, $blockedDomains, true)) {
                $byUri = \App\ActivityPub\InboxProcessor::fetchRemoteNote($q, true, 0);
            }
            if ($byUri) {
                $m = $isHiddenStatus($byUri) ? null : StatusModel::toMasto($byUri, $vid);
                if ($m) $statuses[] = $m;
            }
        }

        if ($wantStatuses) {
            $statusSql = "SELECT * FROM statuses
                          WHERE content LIKE ? ESCAPE '\\'
                            AND visibility='public'
                            AND (expires_at IS NULL OR expires_at='' OR expires_at>?)
                            AND (user_id LIKE 'http%' OR user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))";
            $statusParams = [$qLike, now_iso()];
            if ($vid) {
                $statusSql .= ' AND user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)';
                $statusSql .= ' AND user_id NOT IN (SELECT target_id FROM mutes WHERE user_id=?)';
                $statusParams[] = $vid;
                $statusParams[] = $vid;
            }
            $statusSql .= StatusModel::domainBlockSql('user_id', $blockedDomains);
            $statusSql .= ' ORDER BY created_at DESC LIMIT ?';
            $statusParams[] = $limit;
            $rows = DB::all($statusSql, $statusParams);
            $statuses = array_values(array_filter(array_merge(
                $statuses,
                array_map(fn($s) => $isHiddenStatus($s) ? null : StatusModel::toMasto($s, $vid), $rows)
            )));
            $statuses = array_slice(array_values(array_filter(
                array_combine(array_column($statuses, 'id'), $statuses) ?: []
            )), 0, $limit);
        }

        // ── Hashtags ─────────────────────────────────────────
        if ($wantHashtags) {
            $htRows   = DB::all("SELECT id, name FROM hashtags WHERE name LIKE ? ESCAPE '\\' LIMIT ?", [$qLike, $limit]);
            $hashtags = array_map(function ($h) use ($vid) {
                $following = $vid
                    ? (bool)DB::one('SELECT 1 FROM tag_follows WHERE user_id=? AND hashtag_id=?', [$vid, $h['id']])
                    : false;
                return [
                    'id'        => $h['id'],
                    'name'      => $h['name'],
                    'url'       => ap_url('tags/' . rawurlencode($h['name'])),
                    'history'   => [],
                    'following' => $following,
                ];
            }, $htRows);
        }

        $accounts = array_slice(array_values(array_filter(
            array_combine(array_column($accounts, 'id'), $accounts) ?: []
        )), 0, $limit);

        json_out([
            'accounts' => $accounts,
            'statuses' => $statuses,
            'hashtags' => $hashtags,
        ]);
    }
}

// ── Media ────────────────────────────────────────────────────

class MediaCtrl
{
    public function upload(array $p): void
    {
        $user = require_auth(['write', 'write:media']);
        $file = $_FILES['file'] ?? null;
        if (!$file) err_out('No file uploaded', 422);
        $m = MediaModel::upload($file, $user['id']);
        if (!$m) err_out('Upload failed (type/size not allowed)', 422);
        json_out(MediaModel::toMasto($m));
    }

    public function serve(array $p): void
    {
        // Servir ficheiros de media directamente (avatares, imagens de posts)
        $filename = basename($p['filename'] ?? '');
        if ($filename === '') { http_response_code(404); exit; }

        // Whitelist allowed media extensions to prevent serving executable files
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $allowedMimeByExt = [
            'jpg'  => ['image/jpeg'],
            'jpeg' => ['image/jpeg'],
            'png'  => ['image/png'],
            'gif'  => ['image/gif'],
            'webp' => ['image/webp'],
            'avif' => ['image/avif'],
            'heic' => ['image/heic', 'image/heif'],
            'heif' => ['image/heif', 'image/heic'],
            'mp4'  => ['video/mp4'],
            'webm' => ['video/webm'],
            'mov'  => ['video/quicktime', 'video/mp4'],
            'mp3'  => ['audio/mpeg', 'audio/mp3'],
            'ogg'  => ['audio/ogg', 'video/ogg'],
            'wav'  => ['audio/wav', 'audio/x-wav'],
            'm4a'  => ['audio/mp4', 'audio/x-m4a'],
        ];
        if (!isset($allowedMimeByExt[$ext])) { http_response_code(403); exit; }

        $path = AP_MEDIA_DIR . '/' . $filename;
        if (!file_exists($path) || !is_file($path)) {
            http_response_code(404); exit;
        }

        $mime = mime_content_type($path) ?: 'application/octet-stream';
        if (!in_array($mime, $allowedMimeByExt[$ext], true)) {
            http_response_code(403); exit;
        }
        $size = filesize($path);
        $etag = md5($filename . $size);

        header('Content-Type: ' . $mime);
        header('X-Content-Type-Options: nosniff');
        header('ETag: "' . $etag . '"');
        header('Cache-Control: public, max-age=31536000, immutable');
        header('Access-Control-Allow-Origin: *');
        header('Accept-Ranges: bytes');

        // 304 Not Modified
        $ifNoneMatch = $_SERVER['HTTP_IF_NONE_MATCH'] ?? '';
        if ($ifNoneMatch === '"' . $etag . '"') {
            http_response_code(304); exit;
        }

        // HTTP Range support — required by iOS/Safari/Ivory to play video
        $rangeHeader = $_SERVER['HTTP_RANGE'] ?? '';
        if ($rangeHeader && preg_match('/bytes=(\d*)-(\d*)/i', $rangeHeader, $m)) {
            $start = $m[1] !== '' ? (int)$m[1] : 0;
            $end   = $m[2] !== '' ? (int)$m[2] : $size - 1;
            if ($end >= $size) $end = $size - 1;
            if ($start > $end || $start >= $size) {
                http_response_code(416);
                header('Content-Range: bytes */' . $size);
                exit;
            }
            $length = $end - $start + 1;
            http_response_code(206);
            header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
            header('Content-Length: ' . $length);
            $fh = fopen($path, 'rb');
            fseek($fh, $start);
            $remaining = $length;
            while ($remaining > 0 && !feof($fh)) {
                $chunk = fread($fh, min(65536, $remaining));
                echo $chunk;
                $remaining -= strlen($chunk);
            }
            fclose($fh);
            exit;
        }

        header('Content-Length: ' . $size);
        readfile($path);
        exit;
    }

    public function show(array $p): void
    {
        $user = require_auth('read');
        $m = DB::one('SELECT * FROM media_attachments WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$m) err_out('Not found', 404);
        json_out(MediaModel::toMasto($m));
    }

    public function update(array $p): void
    {
        $user = require_auth(['write', 'write:media']);
        $d    = req_body();
        if (isset($d['description'])) {
            DB::update('media_attachments', ['description' => $d['description']], 'id=? AND user_id=?', [$p['id'], $user['id']]);
        }
        $m = DB::one('SELECT * FROM media_attachments WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$m) err_out('Not found', 404);
        json_out(MediaModel::toMasto($m));
    }
}

// ── Bookmarks ────────────────────────────────────────────────

class BookmarksCtrl
{
    public function index(array $p): void
    {
        $user    = require_auth('read');
        $limit   = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $scanLimit = max(100, min(5000, $limit * 10));
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;

        $sql = 'SELECT b.id, b.status_id, b.created_at FROM bookmarks b WHERE b.user_id=?';
        $par = [$user['id']];
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM bookmarks WHERE user_id=? AND id=?', [$user['id'], $maxId])
                ?? DB::one('SELECT created_at, id FROM bookmarks WHERE user_id=? AND status_id=?', [$user['id'], $maxId]);
            if ($ref) {
                $sql .= ' AND (b.created_at < ? OR (b.created_at = ? AND b.id < ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        if ($sinceId) {
            $ref = DB::one('SELECT created_at, id FROM bookmarks WHERE user_id=? AND id=?', [$user['id'], $sinceId])
                ?? DB::one('SELECT created_at, id FROM bookmarks WHERE user_id=? AND status_id=?', [$user['id'], $sinceId]);
            if ($ref) {
                $sql .= ' AND (b.created_at > ? OR (b.created_at = ? AND b.id > ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        if ($minId) {
            $ref = DB::one('SELECT created_at, id FROM bookmarks WHERE user_id=? AND id=?', [$user['id'], $minId])
                ?? DB::one('SELECT created_at, id FROM bookmarks WHERE user_id=? AND status_id=?', [$user['id'], $minId]);
            if ($ref) {
                $sql .= ' AND (b.created_at > ? OR (b.created_at = ? AND b.id > ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        $sql .= $minId ? ' ORDER BY b.created_at ASC, b.id ASC LIMIT ?' : ' ORDER BY b.created_at DESC, b.id DESC LIMIT ?';
        $par[] = $scanLimit;

        $rows = DB::all($sql, $par);

        $out = [];
        foreach ($rows as $r) {
            $s = StatusModel::byId($r['status_id']);
            if (!$s) continue;
            $m = StatusModel::toMasto($s, $user['id']);
            if (!$m) continue;
            $out[] = $m;
            if (count($out) >= $limit) break;
        }
        if ($minId && $out) { $out = array_reverse($out); }

        if ($rows) {
            $base = ap_url('api/v1/bookmarks');
            header(sprintf('Link: <%s?%s>; rel="next", <%s?%s>; rel="prev"',
                $base, http_build_query(['limit' => $limit, 'max_id' => end($rows)['id']]),
                $base, http_build_query(['limit' => $limit, 'min_id' => reset($rows)['id']])
            ));
        }
        json_out($out);
    }
}

// ── Favourites ───────────────────────────────────────────────

class FavouritesCtrl
{
    public function index(array $p): void
    {
        $user    = require_auth('read');
        $limit   = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $scanLimit = max(100, min(5000, $limit * 10));
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;

        $sql = 'SELECT f.id, f.status_id, f.created_at FROM favourites f WHERE f.user_id=?';
        $par = [$user['id']];
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM favourites WHERE user_id=? AND id=?', [$user['id'], $maxId])
                ?? DB::one('SELECT created_at, id FROM favourites WHERE user_id=? AND status_id=?', [$user['id'], $maxId]);
            if ($ref) {
                $sql .= ' AND (f.created_at < ? OR (f.created_at = ? AND f.id < ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        if ($sinceId) {
            $ref = DB::one('SELECT created_at, id FROM favourites WHERE user_id=? AND id=?', [$user['id'], $sinceId])
                ?? DB::one('SELECT created_at, id FROM favourites WHERE user_id=? AND status_id=?', [$user['id'], $sinceId]);
            if ($ref) {
                $sql .= ' AND (f.created_at > ? OR (f.created_at = ? AND f.id > ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        if ($minId) {
            $ref = DB::one('SELECT created_at, id FROM favourites WHERE user_id=? AND id=?', [$user['id'], $minId])
                ?? DB::one('SELECT created_at, id FROM favourites WHERE user_id=? AND status_id=?', [$user['id'], $minId]);
            if ($ref) {
                $sql .= ' AND (f.created_at > ? OR (f.created_at = ? AND f.id > ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        $sql .= $minId ? ' ORDER BY f.created_at ASC, f.id ASC LIMIT ?' : ' ORDER BY f.created_at DESC, f.id DESC LIMIT ?';
        $par[] = $scanLimit;

        $rows = DB::all($sql, $par);
        $out  = [];
        foreach ($rows as $r) {
            $s = StatusModel::byId($r['status_id']);
            if (!$s) continue;
            $m = StatusModel::toMasto($s, $user['id']);
            if (!$m) continue;
            $out[] = $m;
            if (count($out) >= $limit) break;
        }
        if ($minId && $out) { $out = array_reverse($out); }
        if ($rows) {
            $base = ap_url('api/v1/favourites');
            header(sprintf('Link: <%s?%s>; rel="next", <%s?%s>; rel="prev"',
                $base, http_build_query(['limit' => $limit, 'max_id' => end($rows)['id']]),
                $base, http_build_query(['limit' => $limit, 'min_id' => reset($rows)['id']])
            ));
        }
        json_out($out);
    }
}

// ── Blocks ───────────────────────────────────────────────────

class BlocksCtrl
{
    public function index(array $p): void
    {
        $user = require_auth('read');
        $rows = DB::all('SELECT target_id FROM blocks WHERE user_id=? LIMIT 40', [$user['id']]);
        $out  = array_values(array_filter(array_map(function ($r) {
            $u = UserModel::byId($r['target_id']);
            if ($u) {
                if (!empty($u['is_suspended'])) return null;
                return UserModel::toMasto($u);
            }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$r['target_id']]);
            if ($ra) return UserModel::remoteToMasto($ra);
            return null;
        }, $rows)));
        json_out($out);
    }
}

// ── Mutes ────────────────────────────────────────────────────

class MutesCtrl
{
    public function index(array $p): void
    {
        $user = require_auth('read');
        $rows = DB::all('SELECT target_id FROM mutes WHERE user_id=? LIMIT 40', [$user['id']]);
        $out  = array_values(array_filter(array_map(function ($r) {
            $u = UserModel::byId($r['target_id']);
            if ($u) {
                if (!empty($u['is_suspended'])) return null;
                return UserModel::toMasto($u);
            }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$r['target_id']]);
            if ($ra) return UserModel::remoteToMasto($ra);
            return null;
        }, $rows)));
        json_out($out);
    }
}

// ── Conversations (DMs) ──────────────────────────────────────

class ConversationsCtrl
{
    private function isHiddenFromViewer(string $viewerId, string $targetId): bool
    {
        if ($targetId === '' || $targetId === $viewerId) return false;
        if (DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) return true;
        if (DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) return true;
        if (!str_starts_with($targetId, 'http')) return false;
        $ra = DB::one('SELECT domain FROM remote_actors WHERE id=?', [$targetId]);
        if (!$ra || ($ra['domain'] ?? '') === '') return false;
        return (bool)DB::one(
            'SELECT 1 FROM user_domain_blocks WHERE user_id=? AND domain=?',
            [$viewerId, strtolower((string)$ra['domain'])]
        );
    }

    public function index(array $p): void
    {
        $user  = require_auth('read');
        $limit = max(1, min((int)($_GET['limit'] ?? 20), 40));
        $maxId = $_GET['max_id'] ?? null;
        $blockedDomains = StatusModel::blockedDomains($user['id']);

        // Encontrar todos os posts directos onde o utilizador está envolvido
        // Agrupar por thread (reply_to_id forma a thread) e mostrar o mais recente
        $sql = "SELECT s.*
                FROM statuses s
                WHERE s.visibility='direct'
                  AND s.reblog_of_id IS NULL
                  AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
                  AND (
                    s.user_id=?
                    OR s.id IN (
                        SELECT status_id FROM notifications
                        WHERE user_id=? AND type IN ('mention','direct')
                    )
                  )
                  AND s.user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                  AND s.user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)";
        $par = [now_iso(), $user['id'], $user['id'], $user['id'], $user['id']];
        $sql .= StatusModel::domainBlockSql('s.user_id', $blockedDomains);
        if ($maxId) {
            $ref = DB::one('SELECT created_at FROM statuses WHERE id=?', [$maxId]);
            if ($ref) { $sql .= ' AND s.created_at<?'; $par[] = $ref['created_at']; }
        }
        $sql .= ' ORDER BY s.created_at DESC LIMIT ?'; $par[] = $limit * 3; // buscar mais para agrupar

        $rows = DB::all($sql, $par);

        // Agrupar por conversa: identificar o root de cada thread
        $threads      = []; // thread_root_id => último status
        $threadUnread = [];
        foreach ($rows as $s) {
            // Encontrar o root da thread subindo pelo reply_to_id
            $root = $s['id'];
            $current = $s;
            $depth = 0;
            while ($current['reply_to_id'] && $depth < 10) {
                $parent = StatusModel::byId($current['reply_to_id']);
                if (!$parent || $parent['visibility'] !== 'direct') break;
                $root = $parent['id'];
                $current = $parent;
                $depth++;
            }
            // Guardar o mais recente de cada thread
            if (!isset($threads[$root]) ||
                $s['created_at'] > $threads[$root]['created_at']) {
                $threads[$root] = $s;
            }

            if (!isset($threadUnread[$root])) {
                $threadUnread[$root] = false;
            }
            $hasUnread = (bool)DB::one(
                "SELECT 1 FROM notifications
                 WHERE user_id=? AND status_id=? AND read_at IS NULL
                   AND type IN ('mention','direct')",
                [$user['id'], $s['id']]
            );
            if ($hasUnread) {
                $threadUnread[$root] = true;
            }
        }

        // Ordenar threads pelo último post (uasort preserva as chaves = root status IDs)
        uasort($threads, fn($a, $b) => strcmp($b['created_at'], $a['created_at']));
        $threads = array_slice($threads, 0, $limit, true);

        $out = [];
        foreach ($threads as $rootId => $lastStatus) {
            $sm = StatusModel::toMasto($lastStatus, $user['id']);
            if (!$sm) continue;

            // Construir lista de participantes a partir de toda a thread, para não omitir
            // intervenientes que não aparecem no último post.
            $allIds = [$rootId];
            $queue  = [$rootId];
            $depth  = 0;
            while ($queue && $depth < 20) {
                $ids      = array_splice($queue, 0, 20);
                $phs      = implode(',', array_fill(0, count($ids), '?'));
                $children = DB::all(
                    "SELECT id FROM statuses
                     WHERE reply_to_id IN ($phs) AND visibility='direct'
                       AND (expires_at IS NULL OR expires_at='' OR expires_at>?)",
                    array_merge($ids, [now_iso()])
                );
                foreach ($children as $c) {
                    if (!in_array($c['id'], $allIds, true)) {
                        $allIds[] = $c['id'];
                        $queue[]  = $c['id'];
                    }
                }
                $depth++;
            }

            $accounts = [];
            $seen = [];
            $phs = implode(',', array_fill(0, count($allIds), '?'));
            $threadStatuses = DB::all("SELECT DISTINCT user_id FROM statuses WHERE id IN ($phs)", $allIds);
            foreach ($threadStatuses as $row) {
                $uid = $row['user_id'];
                if (isset($seen[$uid])) continue;
                if ($this->isHiddenFromViewer($user['id'], $uid)) continue;
                $seen[$uid] = true;
                $local = UserModel::byId($uid);
                if ($local) {
                    if (!empty($local['is_suspended'])) continue;
                    $masto = UserModel::toMasto($local, $user['id']);
                    if ($masto) $accounts[] = $masto;
                    continue;
                }
                $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$uid]);
                if ($ra) $accounts[] = UserModel::remoteToMasto($ra);
            }

            // Garantir que o viewer está na lista
            if (!isset($seen[$user['id']])) {
                $viewer = UserModel::byId($user['id']);
                if ($viewer) $accounts[] = UserModel::toMasto($viewer, $user['id']);
            }

            $hasVisibleOther = false;
            foreach ($accounts as $account) {
                if (($account['id'] ?? '') !== $user['id']) {
                    $hasVisibleOther = true;
                    break;
                }
            }
            if (!$hasVisibleOther) continue;

            $out[] = [
                'id'          => (string)$rootId,
                'accounts'    => array_values($accounts),
                'last_status' => $sm,
                'unread'      => (bool)($threadUnread[$rootId] ?? false),
            ];
        }
        json_out($out);
    }

    public function read(array $p): void
    {
        $user   = require_auth(['write', 'write:conversations']);
        $rootId = $p['id'];
        $root   = StatusModel::byId($rootId);
        if (!$root || ($root['visibility'] ?? '') !== 'direct' || !StatusModel::canView($root, $user['id'])) {
            err_out('Not found', 404);
        }

        // BFS: collect all status IDs in this conversation thread so we can
        // mark notifications for every message (not just the root) as read.
        $allIds = [$rootId];
        $queue  = [$rootId];
        $depth  = 0;
        while ($queue && $depth < 20) {
            $ids      = array_splice($queue, 0, 20);
            $phs      = implode(',', array_fill(0, count($ids), '?'));
            $children = DB::all(
                "SELECT id FROM statuses
                 WHERE reply_to_id IN ($phs) AND visibility='direct'
                   AND (expires_at IS NULL OR expires_at='' OR expires_at>?)",
                array_merge($ids, [now_iso()])
            );
            foreach ($children as $c) {
                if (!in_array($c['id'], $allIds, true)) {
                    $allIds[] = $c['id'];
                    $queue[]  = $c['id'];
                }
            }
            $depth++;
        }

        // Mark every notification for statuses in this thread as read
        $phs = implode(',', array_fill(0, count($allIds), '?'));
        DB::run(
            "UPDATE notifications SET read_at=? WHERE user_id=? AND status_id IN ($phs) AND read_at IS NULL",
            array_merge([now_iso(), $user['id']], $allIds)
        );

        $lastStatus = $root;
        foreach ($allIds as $sid) {
            $candidate = ($sid === $rootId) ? $root : StatusModel::byId($sid);
            if ($candidate && $candidate['created_at'] > $lastStatus['created_at']) {
                $lastStatus = $candidate;
            }
        }
        $sm = StatusModel::toMasto($lastStatus, $user['id']);

        // Build participants list from all statuses in this thread
        $accounts = [];
        $seen = [];
        $phs = implode(',', array_fill(0, count($allIds), '?'));
        $threadStatuses = DB::all("SELECT DISTINCT user_id FROM statuses WHERE id IN ($phs)", $allIds);
        foreach ($threadStatuses as $row) {
            $uid = $row['user_id'];
            if (isset($seen[$uid])) continue;
            if ($this->isHiddenFromViewer($user['id'], $uid)) continue;
            $seen[$uid] = true;
            $local = UserModel::byId($uid);
            if ($local) {
                if (!empty($local['is_suspended'])) continue;
                $masto = UserModel::toMasto($local, $user['id']);
                if ($masto) $accounts[] = $masto;
                continue;
            }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$uid]);
            if ($ra) $accounts[] = UserModel::remoteToMasto($ra);
        }
        if (!isset($seen[$user['id']])) {
            $viewer = UserModel::byId($user['id']);
            if ($viewer) $accounts[] = UserModel::toMasto($viewer, $user['id']);
        }

        $hasVisibleOther = false;
        foreach ($accounts as $account) {
            if (($account['id'] ?? '') !== $user['id']) {
                $hasVisibleOther = true;
                break;
            }
        }
        if (!$hasVisibleOther) err_out('Not found', 404);

        json_out(['id' => (string)$rootId, 'accounts' => array_values($accounts), 'last_status' => $sm, 'unread' => false]);
    }
}

// ── Follow requests ──────────────────────────────────────────

class FollowRequestsCtrl
{
    private function isHiddenFromViewer(string $viewerId, string $targetId): bool
    {
        if ($targetId === '' || $targetId === $viewerId) return false;
        if (DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) return true;
        if (DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) return true;
        if (!str_starts_with($targetId, 'http')) return false;
        $ra = DB::one('SELECT domain FROM remote_actors WHERE id=?', [$targetId]);
        if (!$ra || ($ra['domain'] ?? '') === '') return false;
        return (bool)DB::one(
            'SELECT 1 FROM user_domain_blocks WHERE user_id=? AND domain=?',
            [$viewerId, strtolower((string)$ra['domain'])]
        );
    }

    private function relationship(string $viewerId, string $clientId, string $internalId): array
    {
        $domainBlocking = false;
        if (str_starts_with($internalId, 'http')) {
            $ra = DB::one('SELECT domain FROM remote_actors WHERE id=?', [$internalId]);
            if ($ra) {
                $domainBlocking = (bool)DB::one(
                    'SELECT 1 FROM user_domain_blocks WHERE user_id=? AND domain=?',
                    [$viewerId, strtolower((string)$ra['domain'])]
                );
            }
        }

        $activeFollow = DB::one(
            'SELECT notify FROM follows WHERE follower_id=? AND following_id=? AND pending=0',
            [$viewerId, $internalId]
        );

        return [
            'id'                   => $clientId,
            'following'            => $activeFollow !== null,
            'showing_reblogs'      => true,
            'notifying'            => $activeFollow ? (bool)$activeFollow['notify'] : false,
            'languages'            => [],
            'followed_by'          => (bool)DB::one('SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=0', [$internalId, $viewerId]),
            'blocking'             => (bool)DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$viewerId, $internalId]),
            'blocked_by'           => (bool)DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$internalId, $viewerId]),
            'muting'               => (bool)DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$viewerId, $internalId]),
            'muting_notifications' => false,
            'requested'            => (bool)DB::one('SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=1', [$viewerId, $internalId]),
            'requested_by'         => (bool)DB::one('SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=1', [$internalId, $viewerId]),
            'domain_blocking'      => $domainBlocking,
            'endorsed'             => (bool)DB::one('SELECT 1 FROM account_endorsements WHERE user_id=? AND target_id=?', [$viewerId, $internalId]),
            'note'                 => (string)(DB::one('SELECT comment FROM account_notes WHERE user_id=? AND target_id=?', [$viewerId, $internalId])['comment'] ?? ''),
            'muting_expires_at'    => null,
        ];
    }

    public function index(array $p): void
    {
        $user = require_auth('read');
        $limit = max(1, min((int)($_GET['limit'] ?? 40), 80));
        $rows = DB::all(
            'SELECT follower_id FROM follows WHERE following_id=? AND pending=1 ORDER BY created_at DESC LIMIT ?',
            [$user['id'], $limit]
        );
        $out = [];
        foreach ($rows as $r) {
            if ($this->isHiddenFromViewer($user['id'], $r['follower_id'])) continue;
            // Could be local or remote
            $u = UserModel::byId($r['follower_id']);
            if ($u) {
                if (!empty($u['is_suspended'])) continue;
                $masto = UserModel::toMasto($u);
                if ($masto) $out[] = $masto;
                continue;
            }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$r['follower_id']]);
            if ($ra) $out[] = UserModel::remoteToMasto($ra);
        }
        json_out(array_values($out));
    }

    public function authorize(array $p): void
    {
        $user      = require_auth(['follow', 'write', 'write:follows']);
        $clientId  = $p['id'];

        // The client sends the Mastodon account ID: UUID for local users, masto_id (md5)
        // for remote actors. The follows table stores the AP URL for remote actors.
        // Resolve to the actual follower_id used in the follows table.
        $localFollower = UserModel::byId($clientId);
        if ($localFollower && !empty($localFollower['is_suspended'])) {
            $localFollower = null;
        }
        $ra            = null;
        if ($localFollower) {
            $followerId = $clientId;             // local UUID = follower_id in follows
        } else {
            $ra = DB::one('SELECT * FROM remote_actors WHERE masto_id=?', [$clientId]);
            if (!$ra) err_out('Not found', 404);
            $followerId = $ra['id'];             // AP URL = follower_id in follows
        }

        $follow = DB::one('SELECT * FROM follows WHERE follower_id=? AND following_id=? AND pending=1', [$followerId, $user['id']]);
        if (!$follow) err_out('Not found', 404);

        DB::run('UPDATE follows SET pending=0 WHERE follower_id=? AND following_id=?', [$followerId, $user['id']]);
        DB::run('UPDATE users SET follower_count=follower_count+1 WHERE id=?', [$user['id']]);

        if ($localFollower) {
            DB::run('UPDATE users SET following_count=following_count+1 WHERE id=?', [$followerId]);
        }

        // Replace follow_request notification with a follow notification
        DB::delete('notifications', 'user_id=? AND from_acct_id=? AND type=?', [$user['id'], $followerId, 'follow_request']);
        DB::insertIgnore('notifications', [
            'id'           => flake_id(),
            'user_id'      => $user['id'],
            'from_acct_id' => $followerId,
            'type'         => 'follow',
            'status_id'    => null,
            'created_at'   => now_iso(),
        ]);

        // Federate Accept to remote follower
        if ($ra) {
            $targetUrl = actor_url($user['username']);
            $followActivity = [
                'id'     => $followerId . '#follow/' . md5($targetUrl),
                'type'   => 'Follow',
                'actor'  => $followerId,
                'object' => $targetUrl,
            ];
            $accept = Builder::accept($user, $followActivity);
            Delivery::queueToActor($user, $ra, $accept);
        }

        json_out($this->relationship($user['id'], $clientId, $followerId));
    }

    public function reject(array $p): void
    {
        $user     = require_auth(['follow', 'write', 'write:follows']);
        $clientId = $p['id'];

        // Same resolution: client sends masto_id, follows table has AP URL
        $localFollower = UserModel::byId($clientId);
        if ($localFollower && !empty($localFollower['is_suspended'])) {
            $localFollower = null;
        }
        $ra            = null;
        if ($localFollower) {
            $followerId = $clientId;
        } else {
            $ra = DB::one('SELECT * FROM remote_actors WHERE masto_id=?', [$clientId]);
            if (!$ra) err_out('Not found', 404);
            $followerId = $ra['id'];
        }

        $follow = DB::one('SELECT * FROM follows WHERE follower_id=? AND following_id=? AND pending=1', [$followerId, $user['id']]);
        if (!$follow) err_out('Not found', 404);

        DB::delete('follows', 'follower_id=? AND following_id=?', [$followerId, $user['id']]);
        DB::delete('notifications', 'user_id=? AND from_acct_id=? AND type=?', [$user['id'], $followerId, 'follow_request']);

        // Federate Reject to remote follower
        if ($ra) {
            $targetUrl = actor_url($user['username']);
            $followActivity = [
                'id'     => $followerId . '#follow/' . md5($targetUrl),
                'type'   => 'Follow',
                'actor'  => $followerId,
                'object' => $targetUrl,
            ];
            $reject = Builder::reject($user, $followActivity);
            Delivery::queueToActor($user, $ra, $reject);
        }

        json_out($this->relationship($user['id'], $clientId, $followerId));
    }
}

// ── Lists ────────────────────────────────────────────────────

class ListsCtrl
{
    private function isHiddenFromViewer(string $viewerId, string $targetId): bool
    {
        if ($targetId === '' || $targetId === $viewerId) return false;
        if (DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) return true;
        if (DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) return true;
        if (!str_starts_with($targetId, 'http')) return false;
        $ra = DB::one('SELECT domain FROM remote_actors WHERE id=?', [$targetId]);
        if (!$ra || ($ra['domain'] ?? '') === '') return false;
        return (bool)DB::one(
            'SELECT 1 FROM user_domain_blocks WHERE user_id=? AND domain=?',
            [$viewerId, strtolower((string)$ra['domain'])]
        );
    }

    private function fmt(array $l): array
    {
        return ['id' => $l['id'], 'title' => $l['title'], 'replies_policy' => 'list', 'exclusive' => false];
    }

    public function index(array $p): void
    {
        $user = require_auth('read');
        json_out(array_map([$this, 'fmt'], DB::all(
            'SELECT * FROM lists WHERE user_id=? ORDER BY position ASC, created_at ASC',
            [$user['id']]
        )));
    }

    public function create(array $p): void
    {
        $user = require_auth(['write', 'write:lists']);
        $d    = req_body();
        if (array_key_exists('title', $d) && !is_string($d['title'])) {
            err_out('title must be a string', 422);
        }
        $title = trim((string)($d['title'] ?? ''));
        if ($title === '') err_out('title required', 422);
        $id   = uuid();
        $pos  = (int)(DB::one(
            'SELECT COALESCE(MAX(position),0)+1 AS n FROM lists WHERE user_id=?',
            [$user['id']]
        )['n'] ?? 1);
        DB::insert('lists', [
            'id'         => $id,
            'user_id'    => $user['id'],
            'title'      => safe_str($title, 200),
            'position'   => $pos,
            'created_at' => now_iso(),
        ]);
        json_out($this->fmt(DB::one('SELECT * FROM lists WHERE id=?', [$id])));
    }

    public function reorder(array $p): void
    {
        $user = require_auth(['write', 'write:lists']);
        $d    = req_body();
        $ids  = array_values(array_filter((array)($d['order'] ?? []), 'is_string'));
        if (empty($ids)) { json_out([]); return; }
        $db = DB::pdo();
        $st = $db->prepare('UPDATE lists SET position=? WHERE id=? AND user_id=?');
        foreach ($ids as $pos => $id) {
            $st->execute([$pos, $id, $user['id']]);
        }
        json_out([]);
    }

    public function show(array $p): void
    {
        $user = require_auth('read');
        $l = DB::one('SELECT * FROM lists WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$l) err_out('Not found', 404);
        json_out($this->fmt($l));
    }

    public function update(array $p): void
    {
        $user = require_auth(['write', 'write:lists']);
        $l = DB::one('SELECT * FROM lists WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$l) err_out('Not found', 404);
        $d = req_body();
        if (isset($d['title'])) {
            if (!is_string($d['title'])) err_out('title must be a string', 422);
            $title = trim((string)$d['title']);
            if ($title === '') err_out('title required', 422);
            DB::update('lists', ['title' => safe_str($title, 200)], 'id=?', [$p['id']]);
        }
        $l = DB::one('SELECT * FROM lists WHERE id=?', [$p['id']]);
        json_out($this->fmt($l));
    }

    public function delete(array $p): void
    {
        $user = require_auth(['write', 'write:lists']);
        $l = DB::one('SELECT * FROM lists WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$l) err_out('Not found', 404);
        DB::delete('list_accounts', 'list_id=?', [$p['id']]);
        DB::delete('lists', 'id=?', [$p['id']]);
        json_out([]);
    }

    public function accounts(array $p): void
    {
        $user = require_auth('read');
        $l = DB::one('SELECT id FROM lists WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$l) err_out('Not found', 404);
        $limit = max(1, min((int)($_GET['limit'] ?? 40), 80));
        $rows = DB::all(
            'SELECT account_id FROM list_accounts WHERE list_id=? ORDER BY account_id ASC LIMIT ?',
            [$p['id'], $limit]
        );
        $out  = [];
        foreach ($rows as $r) {
            $aid = $r['account_id'];
            if ($this->isHiddenFromViewer($user['id'], $aid)) continue;
            // Internal IDs: UUID for local users, AP URL for remote actors
            $u = UserModel::byId($aid);
            if ($u) {
                if (!empty($u['is_suspended'])) continue;
                $masto = UserModel::toMasto($u);
                if ($masto) $out[] = $masto;
                continue;
            }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$aid]);
            if ($ra) $out[] = UserModel::remoteToMasto($ra);
        }
        json_out(array_values($out));
    }

    /**
     * Resolve a client-facing Mastodon account ID to the internal ID used in the DB.
     * Local users: UUID (same format) → returned as-is.
     * Remote actors: masto_id (md5 of AP URL) → resolved to AP URL.
     */
    private function resolveAccountId(string $clientId): ?string
    {
        $local = UserModel::byId($clientId);
        if ($local && !empty($local['is_suspended'])) {
            return null;
        }
        if ($local) return $local['id'];
        $ra = DB::one('SELECT id FROM remote_actors WHERE masto_id=?', [$clientId]);
        return $ra ? $ra['id'] : null;
    }

    public function addAccounts(array $p): void
    {
        $user = require_auth(['write', 'write:lists']);
        $l = DB::one('SELECT id FROM lists WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$l) err_out('Not found', 404);
        $d = req_body();
        foreach (($d['account_ids'] ?? []) as $clientId) {
            $internalId = $this->resolveAccountId((string)$clientId);
            if (!$internalId) continue;
            if ($this->isHiddenFromViewer($user['id'], $internalId)) continue;
            // Only allow accounts the user follows (enforces list timeline privacy)
            $isFollowing = (bool)DB::one(
                'SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=0',
                [$user['id'], $internalId]
            );
            if (!$isFollowing) continue;
            DB::insertIgnore('list_accounts', ['list_id' => $p['id'], 'account_id' => $internalId]);
        }
        json_out([]);
    }

    public function removeAccounts(array $p): void
    {
        $user = require_auth(['write', 'write:lists']);
        $l = DB::one('SELECT id FROM lists WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$l) err_out('Not found', 404);
        $d = req_body();
        foreach (($d['account_ids'] ?? []) as $clientId) {
            $internalId = $this->resolveAccountId((string)$clientId);
            if (!$internalId) continue;
            DB::delete('list_accounts', 'list_id=? AND account_id=?', [$p['id'], $internalId]);
        }
        json_out([]);
    }
}

// ── Push (stub — Web Push requires external infra) ───────────

class PushCtrl
{
    // Web Push requires external infrastructure (VAPID keys + push gateway) not
    // available on shared hosting. Return 404 for GET and 422 for POST/DELETE so
    // clients (Mastodon iOS, Ivory, etc.) know push is unsupported and disable it
    // gracefully — without showing "Failed to decode response" errors.
    public function show(array $p): void
    {
        err_out('Push not supported', 404);
    }

    public function create(array $p): void
    {
        require_auth(['push', 'write']);
        err_out('Push not supported', 422);
    }

    public function delete(array $p): void
    {
        require_auth(['push', 'write']);
        json_out([]);
    }
}

// ── Misc stubs para compatibilidade com clientes ──────────────

class MiscCtrl
{
    // GET /api/v1/followed_tags — Elk chama isto na inicialização
    public function followedTags(array $p): void
    {
        $user = require_auth('read');

        $limit   = max(1, min((int)($_GET['limit'] ?? 100), 200));
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;

        $rows = DB::all(
            'SELECT tf.id AS follow_id, h.id, h.name
             FROM tag_follows tf
             JOIN hashtags h ON h.id=tf.hashtag_id
             WHERE tf.user_id=?
               ' . ($maxId ? 'AND tf.id < ? ' : '') . '
               ' . ($sinceId ? 'AND tf.id > ? ' : '') . '
               ' . ($minId ? 'AND tf.id > ? ' : '') . '
             ORDER BY ' . ($minId ? 'tf.id ASC' : 'tf.id DESC') . '
             LIMIT ?',
            array_values(array_filter([$user['id'], $maxId, $sinceId, $minId, $limit], fn($v) => $v !== null))
        );
        if ($minId) $rows = array_reverse($rows);

        if ($rows) {
            $base = ap_url('api/v1/followed_tags');
            $firstId = reset($rows)['follow_id'];
            $lastId  = end($rows)['follow_id'];
            header(sprintf(
                'Link: <%s?%s>; rel="next", <%s?%s>; rel="prev"',
                $base,
                http_build_query(['limit' => $limit, 'max_id' => $lastId]),
                $base,
                http_build_query(['limit' => $limit, 'min_id' => $firstId])
            ));
        }

        json_out(array_map(fn($r) => [
            'id'        => $r['id'],
            'name'      => $r['name'],
            'url'       => ap_url('tags/' . rawurlencode($r['name'])),
            'history'   => [],
            'following' => true,
        ], $rows));
    }

    // GET /api/v1/streaming/health
    public function streamingHealth(array $p): void
    {
        json_out(['status' => 'OK']);
    }

    /**
     * GET /api/v1/streaming?stream=user|public|public:local|...
     *
     * Implementação SSE (Server-Sent Events) — padrão Mastodon.
     * Não temos WebSocket, mas SSE funciona perfeitamente para Ivory/Phanpy.
     * O cliente reenvia o Last-Event-ID ao reconectar e recebe apenas eventos novos.
     */
    public function stream(array $p): void
    {
        // Detect WebSocket upgrade requests (Mastodon iOS uses WebSocket exclusively).
        // Our server only supports SSE. Returning a JSON 501 is better than serving SSE
        // content that the WebSocket client cannot parse (which causes "Failed to decode
        // response" in Mastodon iOS).
        // Check multiple signals: some reverse proxies (nginx, LiteSpeed) strip the
        // Upgrade header before passing to PHP, but Sec-WebSocket-Key is more resilient.
        $upgrade = strtolower(trim($_SERVER['HTTP_UPGRADE'] ?? ''));
        $isWebSocket = $upgrade === 'websocket'
                    || isset($_SERVER['HTTP_SEC_WEBSOCKET_KEY'])
                    || isset($_SERVER['HTTP_SEC_WEBSOCKET_VERSION']);
        if ($isWebSocket) {
            json_out(
                ['error' => 'WebSocket streaming is not supported. This server uses SSE (/api/v1/streaming with Accept: text/event-stream).'],
                501
            );
        }

        $stream = $_GET['stream'] ?? '';
        if ($stream === '') {
            $path = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?? '');
            $stream = match ($path) {
                '/api/v1/streaming/user'               => 'user',
                '/api/v1/streaming/public'             => 'public',
                '/api/v1/streaming/public/local'       => 'public:local',
                '/api/v1/streaming/public/media'       => 'public:media',
                '/api/v1/streaming/public/local/media' => 'public:local:media',
                default                                => 'user',
            };
        }
        // Public streams don't require authentication; user streams do
        $isPublicStream = in_array($stream, ['public', 'public:local', 'public:media', 'public:local:media']);
        $user = $isPublicStream ? (authed_user() ?? []) : require_auth('read');
        $lastId = $_SERVER['HTTP_LAST_EVENT_ID'] ?? ($_GET['since'] ?? null);

        // SSE headers obrigatórios
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('X-Accel-Buffering: no');  // desactivar buffer nginx/apache
        header('Access-Control-Allow-Origin: *');

        // Limpar buffers de output
        while (ob_get_level()) ob_end_clean();

        // Dizer ao cliente para reconectar após 30 segundos se a ligação fechar
        echo "retry: 30000\n\n";
        flush();

        // Cursor de tempo para buscar eventos novos
        $since = null;
        if ($lastId) {
            // Last-Event-ID pode ser um status ID ou notification ID
            $r = \App\Models\DB::one('SELECT created_at FROM statuses WHERE id=?', [$lastId])
              ?? \App\Models\DB::one('SELECT created_at FROM notifications WHERE id=?', [$lastId]);
            if ($r) $since = $r['created_at'];
        }
        // Fallback: eventos dos últimos 30 segundos
        if (!$since) {
            $since = gmdate('Y-m-d\TH:i:s', time() - 30) . '.000Z';
        }

        // Poll loop: run up to 25 s then let client reconnect (retry: 30000)
        $deadline = time() + 25;
        while (time() < $deadline && !connection_aborted()) {
            $sent        = false;
            $maxSince    = $since; // track the latest created_at seen this cycle

            if (in_array($stream, ['user', 'home'])) {
                $blockedDomains  = \App\Models\StatusModel::blockedDomains($user['id']);
                $domainFilterSSE = \App\Models\StatusModel::domainBlockSql('s.user_id', $blockedDomains);
                // Novos posts na home timeline
                $rows = \App\Models\DB::all(
                    "SELECT s.* FROM statuses s
                     WHERE (s.user_id=? OR s.user_id IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0))
                     AND s.visibility IN ('public','unlisted','private')
                     AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
                     AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
                     AND s.user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                     AND s.user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)
                     {$domainFilterSSE}
                     AND s.created_at > ?
                     ORDER BY s.created_at ASC, s.id ASC LIMIT 20",
                    [$user['id'], $user['id'], now_iso(), $user['id'], $user['id'], $since]
                );
                foreach ($rows as $s) {
                    $masto = \App\Models\StatusModel::toMasto($s, $user['id']);
                    if (!$masto) continue;
                    $json = json_encode($masto, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                    echo "event: update\n";
                    echo "id: {$s['id']}\n";
                    echo "data: $json\n\n";
                    flush();
                    // Advance cursor to the actual created_at of this event so subsequent
                    // queries don't re-fetch it (using time()-1 was causing duplicate events
                    // for statuses created within the last second of each poll cycle).
                    if ($s['created_at'] > $maxSince) $maxSince = $s['created_at'];
                    $sent = true;
                }

                // Novas notificações
                $notifs = \App\Models\DB::all(
                    "SELECT * FROM notifications WHERE user_id=? AND created_at > ? ORDER BY created_at ASC LIMIT 10",
                    [$user['id'], $since]
                );
                $notifCtrl = new NotificationsCtrl();
                foreach ($notifs as $n) {
                    if (!$notifCtrl->shouldAppearInMainList($n, $user)) continue;
                    $notifObj = $notifCtrl->fmtPublic($n, $user);
                    if (!$notifObj) continue;
                    $json = json_encode($notifObj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                    echo "event: notification\n";
                    echo "id: {$n['id']}\n";
                    echo "data: $json\n\n";
                    flush();
                    if ($n['created_at'] > $maxSince) $maxSince = $n['created_at'];
                    $sent = true;
                }

                // Edited posts (status.update event) — check for posts updated since last poll
                $edited = \App\Models\DB::all(
                    "SELECT s.* FROM statuses s
                     WHERE (
                        s.user_id=?
                        OR (
                            s.user_id IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)
                            AND s.visibility IN ('public','unlisted','private')
                        )
                     )
                     AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
                     AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
                     AND s.user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                     AND s.user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)
                     {$domainFilterSSE}
                     AND s.updated_at > s.created_at AND s.updated_at > ?
                     ORDER BY s.updated_at ASC LIMIT 10",
                    [$user['id'], $user['id'], now_iso(), $user['id'], $user['id'], $since]
                );
                foreach ($edited as $s) {
                    $masto = \App\Models\StatusModel::toMasto($s, $user['id']);
                    if (!$masto) continue;
                    $json = json_encode($masto, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                    echo "event: status.update\n";
                    echo "data: $json\n\n";
                    flush();
                    if ($s['updated_at'] > $maxSince) $maxSince = $s['updated_at'];
                    $sent = true;
                }

                // Deleted posts (delete event) — check tombstones created since last poll
                $deleted = \App\Models\DB::all(
                    "SELECT uri, deleted_at FROM tombstones
                     WHERE deleted_at > ?
                     AND (
                        user_id=?
                        OR (
                            user_id IN (SELECT following_id FROM follows WHERE follower_id=? AND pending=0)
                            AND visibility IN ('public','unlisted','private')
                        )
                     )
                     AND user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                     AND user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)
                     {$domainFilterSSE}
                     ORDER BY deleted_at ASC LIMIT 10",
                    [$since, $user['id'], $user['id'], $user['id'], $user['id']]
                );
                foreach ($deleted as $t) {
                    // Extract the status ID from the URI (last path segment)
                    $parts = explode('/', rtrim($t['uri'], '/'));
                    $delId = end($parts);
                    echo "event: delete\n";
                    echo "data: $delId\n\n";
                    flush();
                    if ($t['deleted_at'] > $maxSince) $maxSince = $t['deleted_at'];
                    $sent = true;
                }
            } elseif (in_array($stream, ['public', 'public:local', 'public:media', 'public:local:media'])) {
                $blockedDomainsPub  = \App\Models\StatusModel::blockedDomains($user['id'] ?? null);
                $domainFilterPub    = \App\Models\StatusModel::domainBlockSql('s.user_id', $blockedDomainsPub);
                $pubUserId = $user['id'] ?? '';
                $mediaOnly = in_array($stream, ['public:media', 'public:local:media'], true);
                $mediaClause = $mediaOnly ? ' AND EXISTS (SELECT 1 FROM media_attachments ma WHERE ma.status_id = s.id)' : '';
                if (in_array($stream, ['public:local', 'public:local:media'], true)) {
                    $rows = \App\Models\DB::all(
                        "SELECT s.* FROM statuses s WHERE s.visibility='public' AND s.local=1
                         AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
                         AND s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1)
                         AND s.user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                         AND s.user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)
                         {$domainFilterPub}
                         {$mediaClause}
                         AND s.created_at > ?
                         ORDER BY s.created_at ASC, s.id ASC LIMIT 20",
                        [now_iso(), $pubUserId, $pubUserId, $since]
                    );
                } else {
                    $rows = \App\Models\DB::all(
                        "SELECT s.* FROM statuses s WHERE s.visibility='public'
                         AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
                         AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
                         AND s.user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                         AND s.user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)
                         {$domainFilterPub}
                         {$mediaClause}
                         AND s.created_at > ?
                         ORDER BY s.created_at ASC, s.id ASC LIMIT 20",
                        [now_iso(), $pubUserId, $pubUserId, $since]
                    );
                }
                foreach ($rows as $s) {
                    $masto = \App\Models\StatusModel::toMasto($s, $user['id'] ?? null);
                    if (!$masto) continue;
                    $json = json_encode($masto, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                    echo "event: update\n";
                    echo "id: {$s['id']}\n";
                    echo "data: $json\n\n";
                    flush();
                    if ($s['created_at'] > $maxSince) $maxSince = $s['created_at'];
                    $sent = true;
                }
            }

            // Advance cursor to the latest event we've seen this cycle
            if ($maxSince !== $since) $since = $maxSince;

            // Heartbeat se não enviou nada
            if (!$sent) {
                echo ": heartbeat\n\n";
                flush();
            }

            if (time() < $deadline && !connection_aborted()) {
                sleep(2);
            }
        }
    }
}
