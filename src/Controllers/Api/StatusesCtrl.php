<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, StatusModel, RemoteActorModel, PollModel};
use App\ActivityPub\{Builder, Delivery};

class StatusesCtrl
{
    private static function looksBrokenCard(?array $row): bool
    {
        if (!$row) return false;
        foreach (['title', 'description', 'provider', 'image'] as $key) {
            $val = trim((string)($row[$key] ?? ''));
            if ($val === '') continue;
            if (str_contains($val, '<meta') || str_contains($val, '<link') || str_contains($val, '<script')) {
                return true;
            }
            if ($key !== 'image' && preg_match('/<[^>]+>/', $val)) return true;
        }
        return false;
    }

    private static function metaTagValue(string $html, string $attr, string $name): string
    {
        if (class_exists(\DOMDocument::class)) {
            $prev = libxml_use_internal_errors(true);
            $doc  = new \DOMDocument();
            if (@$doc->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_NOWARNING | LIBXML_NOERROR)) {
                $xpath = new \DOMXPath($doc);
                $query = sprintf('//meta[translate(@%s,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="%s"]/@content', $attr, strtolower($name));
                $nodes = $xpath->query($query);
                if ($nodes && $nodes->length > 0) {
                    $value = trim((string)$nodes->item(0)?->nodeValue);
                    libxml_clear_errors();
                    libxml_use_internal_errors($prev);
                    return html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                }
            }
            libxml_clear_errors();
            libxml_use_internal_errors($prev);
        }

        $quotedAttr = preg_quote($attr, '/');
        $quotedName = preg_quote($name, '/');
        if (preg_match('/<meta\b[^>]*\b' . $quotedAttr . '=["\']' . $quotedName . '["\'][^>]*\bcontent=["\']([^"\']*)["\']/i', $html, $m)) {
            return html_entity_decode(trim($m[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        if (preg_match('/<meta\b[^>]*\bcontent=["\']([^"\']*)["\'][^>]*\b' . $quotedAttr . '=["\']' . $quotedName . '["\']/i', $html, $m)) {
            return html_entity_decode(trim($m[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        return '';
    }

    private function requireVisibleStatus(string $id, ?string $viewerId): array
    {
        $s = StatusModel::byId($id);
        if (!$s || !StatusModel::canView($s, $viewerId)) err_out('Not found', 404);
        return $s;
    }

    public function show(array $p): void
    {
        $viewer = authed_user();
        $s = $this->requireVisibleStatus($p['id'], $viewer['id'] ?? null);
        $out = StatusModel::toMasto($s, $viewer['id'] ?? null);
        if (!$out) err_out('Not found', 404);
        json_out($out);
    }

    public function context(array $p): void
    {
        $viewer = authed_user();
        $s = $this->requireVisibleStatus($p['id'], $viewer['id'] ?? null);
        $vid = $viewer['id'] ?? null;

        $ancestors = [];
        $cur = $s; $depth = 0;
        while ($cur['reply_to_id'] && ++$depth <= 20) {
            $par = StatusModel::byId($cur['reply_to_id']);
            // reply_to_id may be an AP URL for posts from unfollowed accounts
            if (!$par && str_starts_with($cur['reply_to_id'], 'http')) {
                $par = StatusModel::byUri($cur['reply_to_id'])
                    ?? \App\ActivityPub\InboxProcessor::fetchRemoteNote($cur['reply_to_id'], false, 0);
            }
            if (!$par) break;
            if (!StatusModel::canView($par, $vid)) { $cur = $par; continue; }
            $m = StatusModel::toMasto($par, $vid);
            if ($m) array_unshift($ancestors, $m);
            $cur = $par;
        }

        // BFS to collect all descendants, not just direct replies.
        // reply_to_id can be a UUID or a full AP URI (fallback stored when parent wasn't cached),
        // so each level queries by both id and uri of the parent.
        $descRows = [];
        $queue    = [[$s['id'], $s['uri']]];
        $seen     = [$s['id'] => true];
        while ($queue && count($descRows) < 200) {
            [$pId, $pUri] = array_shift($queue);
            $children = DB::all(
                'SELECT * FROM statuses WHERE reply_to_id IN (?,?) ORDER BY created_at ASC LIMIT 40',
                [$pId, $pUri]
            );
            foreach ($children as $child) {
                if (!isset($seen[$child['id']])) {
                    $seen[$child['id']] = true;
                    $descRows[] = $child;
                    $queue[] = [$child['id'], $child['uri']];
                }
            }
        }
        $descendants = array_values(array_filter(array_map(
            fn($r) => StatusModel::canView($r, $vid) ? StatusModel::toMasto($r, $vid) : null,
            $descRows
        )));

        json_out(['ancestors' => $ancestors, 'descendants' => $descendants]);
    }

    public function rebloggedBy(array $p): void
    {
        $viewer = authed_user();
        $this->requireVisibleStatus($p['id'], $viewer['id'] ?? null);
        $rows = DB::all(
            'SELECT user_id FROM (
                SELECT user_id, created_at FROM reblogs WHERE status_id=?
                UNION
                SELECT user_id, created_at FROM statuses WHERE reblog_of_id=?
             )
             ORDER BY created_at DESC
             LIMIT 40',
            [$p['id'], $p['id']]
        );
        json_out($this->resolveAccounts(array_column($rows, 'user_id')));
    }

    public function favouritedBy(array $p): void
    {
        $viewer = authed_user();
        $this->requireVisibleStatus($p['id'], $viewer['id'] ?? null);
        $rows = DB::all('SELECT user_id FROM favourites WHERE status_id=? LIMIT 40', [$p['id']]);
        json_out($this->resolveAccounts(array_column($rows, 'user_id')));
    }

    /** Batch-resolve a list of user IDs (local or remote) to Mastodon account objects. */
    private function resolveAccounts(array $uids): array
    {
        if (!$uids) return [];
        $ph = implode(',', array_fill(0, count($uids), '?'));
        $local  = DB::all("SELECT * FROM users WHERE id IN ($ph)", $uids);
        $byId   = [];
        foreach ($local as $u) $byId[$u['id']] = UserModel::toMasto($u);

        $remoteIds = array_values(array_diff($uids, array_keys($byId)));
        if ($remoteIds) {
            $ph2    = implode(',', array_fill(0, count($remoteIds), '?'));
            $remote = DB::all("SELECT * FROM remote_actors WHERE id IN ($ph2)", $remoteIds);
            foreach ($remote as $ra) $byId[$ra['id']] = UserModel::remoteToMasto($ra);
        }

        return array_values(array_filter(array_map(fn($id) => $byId[$id] ?? null, $uids)));
    }

    private static function immediateTagsForContent(string $content): array
    {
        $out = [];
        foreach (extract_tags($content) as $tag) {
            $ht = DB::one('SELECT id, name FROM hashtags WHERE name=?', [$tag]);
            if ($ht) {
                $out[] = ['id' => $ht['id'], 'name' => $ht['name'], 'url' => ap_url('tags/' . rawurlencode($ht['name']))];
            } else {
                $out[] = ['id' => md5($tag), 'name' => $tag, 'url' => ap_url('tags/' . rawurlencode($tag))];
            }
        }
        return $out;
    }

    private function queueVisibilityAwareDelivery(array $user, array $status, array $activity, bool $includeRelays = false): void
    {
        $visibility = $status['visibility'] ?? 'public';
        if ($visibility !== 'direct') {
            Delivery::queueToFollowers($user, $activity);
            if ($includeRelays && $visibility === 'public') {
                Delivery::queueToRelays($user, $activity);
            }
        }

        $seenRemoteMentions = [];
        foreach (extract_mentions($status['content'] ?? '') as $m) {
            if (is_local($m['domain'] ?? '')) continue;
            $key = strtolower($m['username'] . '@' . ($m['domain'] ?? ''));
            if (isset($seenRemoteMentions[$key])) continue;
            $seenRemoteMentions[$key] = true;
            $remote = RemoteActorModel::fetchByAcct($m['username'], $m['domain'] ?? '');
            if ($remote) Delivery::queueToActor($user, $remote, $activity);
        }
    }

    public function create(array $p): void
    {
        $user = require_auth('write');
        rate_limit_enforce('statuses_create:' . $user['id'], 20, 300, 'Rate limit exceeded for posting');
        $d    = req_body();
        $rawStatus = $d['status'] ?? '';
        if ($rawStatus !== '' && !is_string($rawStatus)) {
            err_out('status must be a string', 422);
        }
        $text = trim((string)$rawStatus);
        $mediaIds = array_values(array_filter((array)($d['media_ids'] ?? []), fn($v) => is_string($v) && $v !== ''));
        $poll = is_array($d['poll'] ?? null) ? $d['poll'] : null;
        $d['media_ids'] = $mediaIds;
        $requestedVisibility = (string)($d['visibility'] ?? 'public');
        $d['visibility'] = in_array($requestedVisibility, ['public', 'unlisted', 'private', 'direct'], true)
            ? $requestedVisibility
            : 'public';

        // Idempotency-Key: Mastodon iOS sends this header to deduplicate retries.
        // If we've already processed a request with this key for this user, return
        // the existing status instead of creating a duplicate.
        $idempotencyKey = $_SERVER['HTTP_IDEMPOTENCY_KEY'] ?? null;
        if ($idempotencyKey) {
            try {
                $existing = DB::one(
                    'SELECT * FROM statuses WHERE user_id=? AND idempotency_key=?',
                    [$user['id'], $idempotencyKey]
                );
                if ($existing) {
                    $m = StatusModel::toMasto($existing, $user['id']);
                    if ($m) json_out($m);
                }
            } catch (\Throwable $e) {
                error_log('[Starling] statuses.create idempotency lookup skipped: ' . $e->getMessage());
            }
        }

        if (!$text && empty($mediaIds) && !$poll) err_out('status, media_ids or poll required', 422);
        if (mb_strlen($text) > AP_POST_CHARS)  err_out('Status too long', 422);
        if (count($mediaIds) > 4) err_out('Too many media attachments', 422);
        if ($poll && $mediaIds) err_out('Polls cannot have media attachments', 422);
        if ($poll && !empty($d['quote_id'])) err_out('Polls cannot quote another post', 422);
        if (!empty($d['expires_in']) && (int)$d['expires_in'] < 300) err_out('Auto-delete must be at least 5 minutes', 422);

        if ($mediaIds) {
            $ph = implode(',', array_fill(0, count($mediaIds), '?'));
            $owned = DB::all(
                "SELECT id FROM media_attachments WHERE user_id=? AND status_id IS NULL AND id IN ($ph)",
                array_merge([$user['id']], $mediaIds)
            );
            if (count($owned) !== count(array_unique($mediaIds))) {
                err_out('Invalid media_ids', 422);
            }
        }

        if (!empty($d['in_reply_to_id'])) {
            $parent = StatusModel::byId((string)$d['in_reply_to_id']);
            if (!$parent || !StatusModel::canView($parent, $user['id'])) err_out('Cannot reply to this post', 422);
        }

        // Validate quoted post visibility — prevents quoting private/direct posts
        if (!empty($d['quote_id'])) {
            $quoted = StatusModel::byId($d['quote_id']);
            if (!$quoted || !StatusModel::canView($quoted, $user['id'])) {
                err_out('Cannot quote this post', 422);
            }
        }

        $status = null;
        try {
            $status = StatusModel::create($d, $user);
            if ($poll) {
                PollModel::createForStatus($status['id'], $poll);
                $status = StatusModel::byId($status['id']) ?? $status;
            }

            // Persist the idempotency key so future retries with the same key get this status back
            if ($idempotencyKey) {
                try {
                    DB::update('statuses', ['idempotency_key' => $idempotencyKey], 'id=?', [$status['id']]);
                } catch (\Throwable) {} // ignore if column not yet added (old install pre-migration)
            }

            $activity = null;
            try {
                $activity = Builder::create($status, $user);
            } catch (\Throwable $e) {
                error_log('[Starling] statuses.create Builder::create failed: ' . $e->getMessage());
            }

            $isDirect = ($status['visibility'] === 'direct');
            $mentions = extract_mentions($text);

            try {
                // Local mention notifications (fast DB — done synchronously before response)
                $seenLocalMentions = [];
                foreach ($mentions as $m) {
                    if (is_local($m['domain'] ?? '')) {
                        $target = UserModel::byUsername($m['username']);
                        if ($target && !isset($seenLocalMentions[$target['id']])) {
                            $seenLocalMentions[$target['id']] = true;
                            DB::insertIgnore('notifications', [
                                'id' => flake_id(), 'user_id' => $target['id'], 'from_acct_id' => $user['id'],
                                'type' => 'mention', 'status_id' => $status['id'],
                                'read_at' => null, 'created_at' => now_iso(),
                            ]);
                        }
                    }
                }

                // 'status' notifications: alert local followers who have notify=true (fast DB)
                if (!$isDirect) {
                    $notifyFollowers = DB::all(
                        'SELECT follower_id FROM follows WHERE following_id=? AND pending=0 AND notify=1
                         AND follower_id IN (SELECT id FROM users WHERE is_suspended=0)',
                        [$user['id']]
                    );
                    foreach ($notifyFollowers as $row) {
                        $alreadyMentioned = DB::one(
                            'SELECT 1 FROM notifications WHERE user_id=? AND status_id=? AND type=?',
                            [$row['follower_id'], $status['id'], 'mention']
                        );
                        if ($alreadyMentioned) continue;
                        DB::insertIgnore('notifications', [
                            'id'           => flake_id(),
                            'user_id'      => $row['follower_id'],
                            'from_acct_id' => $user['id'],
                            'type'         => 'status',
                            'status_id'    => $status['id'],
                            'read_at'      => null,
                            'created_at'   => now_iso(),
                        ]);
                    }
                }
            } catch (\Throwable $e) {
                error_log('[Starling] statuses.create notifications failed: ' . $e->getMessage());
            }

            if ($activity) {
                try {
                    // Queue all federation deliveries. Delivery::enqueue() already schedules a
                    // non-blocking internal wake-up, so we should not also drain the queue here.
                    $this->queueVisibilityAwareDelivery($user, $status, $activity, true);
                } catch (\Throwable $e) {
                    error_log('[Starling] statuses.create federation queue failed: ' . $e->getMessage());
                }
            }

            try {
                // Link card fetch runs after the response is sent.
                defer_after_response(fn() => self::fetchCard($status, true));
            } catch (\Throwable $e) {
                error_log('[Starling] statuses.create deferred card fetch failed: ' . $e->getMessage());
            }

            $out = null;
            try {
                $out = StatusModel::toMasto($status, $user['id']);
            } catch (\Throwable $e) {
                error_log('[Starling] statuses.create serialization failed: ' . $e->getMessage());
            }
            if ($out) {
                json_out($out);
            }
            $fresh = StatusModel::byId($status['id']);
            if ($fresh) {
                $retry = StatusModel::toMasto($fresh, $user['id']);
                if ($retry) json_out($retry);
            }
            err_out('Post created, but could not be serialized', 500);
        } catch (\Throwable $e) {
            if ($status && !empty($status['id'])) {
                error_log('[Starling] statuses.create recovered after partial failure: ' . $e->getMessage());
                $fresh = StatusModel::byId($status['id']);
                if ($fresh) {
                    try {
                        $out = StatusModel::toMasto($fresh, $user['id']);
                        if ($out) json_out($out);
                    } catch (\Throwable) {}
                }
            }
            throw $e;
        }
    }

    public function delete(array $p): void
    {
        $user = require_auth('write');
        $s    = StatusModel::byId($p['id']);
        if (!$s) err_out('Not found', 404);
        if ($s['user_id'] !== $user['id']) err_out('Forbidden', 403);

        $result   = StatusModel::toMasto($s, $user['id']);
        $activity = Builder::delete($s['uri'], $user, $s);
        StatusModel::delete($p['id'], $user['id']);
        $this->queueVisibilityAwareDelivery($user, $s, $activity, ($s['visibility'] ?? 'public') === 'public');
        json_out($result);
    }

    public function edit(array $p): void
    {
        $user = require_auth('write');
        $s    = StatusModel::byId($p['id']);
        if (!$s || $s['user_id'] !== $user['id']) err_out('Not found or forbidden', 403);
        if (!empty($s['reblog_of_id'])) err_out('Cannot edit a boost', 422);

        $d   = req_body();
        if (PollModel::byStatusId($s['id']) && isset($d['poll'])) err_out('Editing polls is not supported', 422);
        if (array_key_exists('expires_in', $d) && !empty($d['expires_in']) && (int)$d['expires_in'] < 300) {
            err_out('Auto-delete must be at least 5 minutes', 422);
        }
        if (isset($d['visibility'])) {
            $requestedVisibility = (string)$d['visibility'];
            $d['visibility'] = in_array($requestedVisibility, ['public', 'unlisted', 'private', 'direct'], true)
                ? $requestedVisibility
                : 'public';
        }
        $now = now_iso();
        $upd = ['updated_at' => $now];
        $newContent = $s['content'];
        if (isset($d['status'])) {
            // Clients like Ivory may send back the rendered HTML instead of plain text.
            // Local posts store plain text; text_to_html() converts on read.
            // If we receive HTML here, strip it to plain text to avoid double-encoding.
            $newContent = $d['status'];
            if ($newContent !== strip_tags($newContent)) {
                $newContent = html_to_plain($newContent);
            }
            if (mb_strlen($newContent) > AP_POST_CHARS) err_out('Status too long', 422);
            $upd['content'] = $newContent;
        }
        if (isset($d['spoiler_text'])) $upd['cw']       = $d['spoiler_text'];
        if (isset($d['sensitive']))    $upd['sensitive'] = (int)bool_val($d['sensitive']);
        if (isset($d['visibility']))   $upd['visibility'] = $d['visibility'];
        if (array_key_exists('expires_in', $d)) {
            $expireIn = (int)($d['expires_in'] ?? 0);
            $upd['expires_at'] = $expireIn > 0 ? gmdate('Y-m-d\TH:i:s\Z', time() + $expireIn) : null;
        }

        $changed = (
            (($upd['content'] ?? $s['content']) !== $s['content']) ||
            (($upd['cw'] ?? $s['cw']) !== $s['cw']) ||
            ((int)($upd['sensitive'] ?? $s['sensitive']) !== (int)$s['sensitive']) ||
            (($upd['visibility'] ?? $s['visibility']) !== $s['visibility']) ||
            (($upd['expires_at'] ?? ($s['expires_at'] ?? null)) !== ($s['expires_at'] ?? null))
        );
        if (!$changed) {
            json_out(StatusModel::toMasto($s, $user['id']));
        }

        DB::insert('status_edits', [
            'id'         => uuid(),
            'status_id'  => $s['id'],
            'content'    => $s['content'],
            'cw'         => $s['cw'],
            'sensitive'  => (int)$s['sensitive'],
            'created_at' => $now,
        ]);
        DB::update('statuses', $upd, 'id=?', [$s['id']]);

        // Re-index hashtags if content changed
        if (isset($upd['content'])) {
            DB::delete('status_hashtags', 'status_id=?', [$s['id']]);
            foreach (extract_tags($upd['content']) as $tag) {
                DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tag, 'created_at' => $now]);
                $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tag]);
                if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $s['id'], 'hashtag_id' => $ht['id']]);
            }
        }

        $updated = StatusModel::byId($s['id']);

        // Federate Update{Note} — queued for async delivery
        $updateActivity = Builder::update($updated, $user);
        $this->queueVisibilityAwareDelivery($user, $updated, $updateActivity);
        // Refresh link preview cache after edits that may have changed the first URL.
        defer_after_response(fn() => self::fetchCard($updated, true));

        $result = StatusModel::toMasto($updated, $user['id']);
        if (isset($upd['content']) && $result) {
            if (empty($result['tags'])) {
                $result['tags'] = self::immediateTagsForContent((string)$upd['content']);
            }
            if (($result['card'] ?? null) === null) {
                $result['card'] = self::fetchCard($updated);
            }
        }

        json_out($result);
    }

    public function reblog(array $p): void
    {
        $user = require_auth('write');
        $orig = StatusModel::byId($p['id']);
        if (!$orig) err_out('Not found', 404);
        if (!in_array($orig['visibility'], ['public', 'unlisted'])) err_out('Forbidden', 403);

        if (!DB::one('SELECT 1 FROM reblogs WHERE user_id=? AND status_id=?', [$user['id'], $orig['id']])) {
            $rbId = flake_id(); $now = now_iso();
            DB::insertIgnore('statuses', [
                'id' => $rbId, 'uri' => ap_url('objects/' . $rbId), 'user_id' => $user['id'],
                'reply_to_id' => null, 'reply_to_uid' => null, 'reblog_of_id' => $orig['id'],
                'content' => '', 'cw' => '', 'visibility' => 'public', 'language' => $orig['language'],
                'sensitive' => 0, 'local' => 1, 'reply_count' => 0, 'reblog_count' => 0,
                'favourite_count' => 0, 'created_at' => $now, 'updated_at' => $now,
            ]);
            DB::insertIgnore('reblogs', [
                'id' => uuid(), 'user_id' => $user['id'], 'status_id' => $orig['id'],
                'reblog_status_id' => $rbId, 'created_at' => $now,
            ]);
            DB::run('UPDATE statuses SET reblog_count=reblog_count+1 WHERE id=?', [$orig['id']]);
            DB::run('UPDATE users SET status_count=status_count+1 WHERE id=?', [$user['id']]);
            UserModel::invalidateCountSyncCache($user['id']);
            // Only notify local post authors (remote authors are notified via federated Announce)
            if (UserModel::byId($orig['user_id'])) {
                DB::insertIgnore('notifications', [
                    'id' => flake_id(), 'user_id' => $orig['user_id'], 'from_acct_id' => $user['id'],
                    'type' => 'reblog', 'status_id' => $orig['id'], 'read_at' => null, 'created_at' => $now,
                ]);
            }
            $boost = StatusModel::byId($rbId);
            if ($boost) {
                Delivery::queueToFollowers($user, Builder::announce($boost, $orig, $user));
            }
        }
        // Devolver o boost (não o original) — o cliente espera o status com reblog:{...}
        $rb = DB::one('SELECT * FROM reblogs WHERE user_id=? AND status_id=?', [$user['id'], $orig['id']]);
        $boostStatus = $rb ? StatusModel::byId($rb['reblog_status_id']) : null;
        json_out(StatusModel::toMasto($boostStatus ?: StatusModel::byId($orig['id']), $user['id']));
    }

    public function unreblog(array $p): void
    {
        $user = require_auth('write');
        $orig = StatusModel::byId($p['id']);
        if (!$orig) err_out('Not found', 404);

        $rb = DB::one('SELECT * FROM reblogs WHERE user_id=? AND status_id=?', [$user['id'], $orig['id']]);
        if ($rb) {
            DB::delete('reblogs',        'user_id=? AND status_id=?',                        [$user['id'], $orig['id']]);
            DB::delete('statuses',       'id=?',                                              [$rb['reblog_status_id']]);
            DB::delete('notifications',  'from_acct_id=? AND status_id=? AND type=?',        [$user['id'], $orig['id'], 'reblog']);
            DB::run('UPDATE statuses SET reblog_count=MAX(0,reblog_count-1) WHERE id=?', [$orig['id']]);
            DB::run('UPDATE users SET status_count=MAX(0,status_count-1) WHERE id=?',   [$user['id']]);
            UserModel::invalidateCountSyncCache($user['id']);
            $boost = [
                'id'         => $rb['reblog_status_id'],
                'created_at' => $rb['created_at'],
            ];
            Delivery::queueToFollowers($user, Builder::undoAnnounce($boost, $orig, $user));
        }
        json_out(StatusModel::toMasto(StatusModel::byId($orig['id']), $user['id']));
    }

    public function favourite(array $p): void
    {
        $user = require_auth('write');
        $s    = $this->requireVisibleStatus($p['id'], $user['id']);

        $alreadyFavourited = (bool)DB::one('SELECT 1 FROM favourites WHERE user_id=? AND status_id=?', [$user['id'], $s['id']]);
        DB::insertIgnore('favourites', [
            'id' => uuid(), 'user_id' => $user['id'], 'status_id' => $s['id'], 'created_at' => now_iso()
        ]);
        if (!$alreadyFavourited) {
            DB::run('UPDATE statuses SET favourite_count=favourite_count+1 WHERE id=?', [$s['id']]);
        }

        // Only notify local post authors (remote authors are notified via federated Like)
        $owner = UserModel::byId($s['user_id']);
        if ($owner && !$alreadyFavourited) {
            DB::insertIgnore('notifications', [
                'id' => flake_id(), 'user_id' => $s['user_id'], 'from_acct_id' => $user['id'],
                'type' => 'favourite', 'status_id' => $s['id'], 'read_at' => null, 'created_at' => now_iso(),
            ]);
        } elseif (!$owner) {
            // Federate Like to remote author — queued
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$s['user_id']]);
            if ($ra) Delivery::queueToActor($user, $ra, Builder::like($s, $user));
        }

        json_out(StatusModel::toMasto(StatusModel::byId($s['id']), $user['id']));
    }

    public function unfavourite(array $p): void
    {
        $user = require_auth('write');
        $s    = $this->requireVisibleStatus($p['id'], $user['id']);

        $wasFavourited = (bool)DB::one('SELECT 1 FROM favourites WHERE user_id=? AND status_id=?', [$user['id'], $s['id']]);
        DB::delete('favourites',     'user_id=? AND status_id=?',                        [$user['id'], $s['id']]);
        DB::delete('notifications',  'from_acct_id=? AND status_id=? AND type=?',        [$user['id'], $s['id'], 'favourite']);
        if ($wasFavourited) {
            DB::run('UPDATE statuses SET favourite_count=MAX(0,favourite_count-1) WHERE id=?', [$s['id']]);
        }

        // Federate Undo{Like} to remote author — queued
        if ($wasFavourited) {
            $owner = UserModel::byId($s['user_id']);
            if (!$owner) {
                $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$s['user_id']]);
                if ($ra) Delivery::queueToActor($user, $ra, Builder::undoLike($s, $user));
            }
        }

        json_out(StatusModel::toMasto(StatusModel::byId($s['id']), $user['id']));
    }

    public function bookmark(array $p): void
    {
        $user = require_auth('write');
        $s    = $this->requireVisibleStatus($p['id'], $user['id']);
        DB::insertIgnore('bookmarks', ['id' => uuid(), 'user_id' => $user['id'], 'status_id' => $s['id'], 'created_at' => now_iso()]);
        json_out(StatusModel::toMasto($s, $user['id']));
    }

    public function unbookmark(array $p): void
    {
        $user = require_auth('write');
        $s    = $this->requireVisibleStatus($p['id'], $user['id']);
        DB::delete('bookmarks', 'user_id=? AND status_id=?', [$user['id'], $s['id']]);
        json_out(StatusModel::toMasto($s, $user['id']));
    }

    public function card(array $p): void
    {
        $viewer = authed_user();
        $s = $this->requireVisibleStatus($p['id'], $viewer['id'] ?? null);
        // Mastodon spec: returns null when no preview card could be generated.
        // Returning {} (empty object) would cause Swift Codable to fail decoding PreviewCard?.
        json_out(self::fetchCard($s));
    }

    /**
     * Extrair o primeiro URL do conteúdo do post e obter o card (Open Graph).
     * Resultado em cache na tabela link_cards.
     */
    public static function fetchCard(array $s, bool $increment = false): ?array
    {
        $isLocal    = (int)($s['local'] ?? 1);
        $rawContent = $s['content'] ?? '';

        // Extrair URL: para posts remotos em HTML, tentar <a href> primeiro (excluindo menções/hashtags)
        $url = null;
        if (!$isLocal && strip_tags($rawContent) !== $rawContent) {
            if (preg_match_all('/<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>/i', $rawContent, $hrefs)) {
                foreach ($hrefs[1] as $href) {
                    if (!str_starts_with($href, 'http')) continue;
                    $hDomain = parse_url($href, PHP_URL_HOST) ?? '';
                    if ($hDomain === AP_DOMAIN) continue;
                    // Saltar links de menções e hashtags
                    $hPath = parse_url($href, PHP_URL_PATH) ?? '';
                    if (str_contains($hPath, '/users/') || str_contains($hPath, '/tags/') || str_contains($hPath, '/tag/')) continue;
                    $url = $href;
                    break;
                }
            }
        }

        // Fallback: extrair URL de texto simples
        if (!$url) {
            $textContent = $isLocal ? $rawContent : strip_tags($rawContent);
            if (!preg_match('~https?://[^\s<>"\')\]]+~', $textContent, $m)) return null;
            $url = rtrim($m[0], '.,;:');
        }

        $normalizedUrl = normalize_http_url($url);

        // Verificar cache pelo URL original e pela versão normalizada
        $cached = DB::one('SELECT * FROM link_cards WHERE url=?', [$url])
               ?? DB::one('SELECT * FROM link_cards WHERE url=?', [$normalizedUrl]);
        if ($cached && !self::looksBrokenCard($cached)) {
            // Refresh fetched_at so recently re-shared links stay inside the trending window
            if ($increment) DB::pdo()->prepare(
                "UPDATE link_cards SET share_count = share_count + 1, fetched_at = ? WHERE url = ?"
            )->execute([now_iso(), $cached['url']]);
            return self::cardObject($cached);
        }

        if (!RemoteActorModel::isSafeUrl($normalizedUrl)) return null;

        // Do not follow redirects here: redirects can invalidate safety checks and
        // preview cards are optional, so failing closed is preferable on shared hosting.
        $ch = curl_init($normalizedUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => AP_SOFTWARE . '/' . AP_VERSION . ' (+https://' . AP_DOMAIN . ')',
            CURLOPT_HTTPHEADER     => ['Accept: text/html'],
        ]);
        $html = curl_exec($ch);
        $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        if (!$html) return null;

        // Verificar cache pelo URL final (pode ter sido armazenado antes por outra rota)
        if ($finalUrl && $finalUrl !== $normalizedUrl) {
            $cached = DB::one('SELECT * FROM link_cards WHERE url=?', [$finalUrl]);
            if ($cached && !self::looksBrokenCard($cached)) {
                if ($increment) DB::pdo()->prepare(
                    "UPDATE link_cards SET share_count = share_count + 1, fetched_at = ? WHERE url = ?"
                )->execute([now_iso(), $finalUrl]);
                // Store the original URL as a cache alias only. It must not duplicate the
                // canonical row's share_count, otherwise trends/links double-counts the same card.
                DB::insertIgnore('link_cards', array_merge($cached, ['url' => $url, 'share_count' => 0]));
                if ($normalizedUrl !== $url) {
                    DB::insertIgnore('link_cards', array_merge($cached, ['url' => $normalizedUrl, 'share_count' => 0]));
                }
                return self::cardObject($cached);
            }
        }

        // Parsear meta OG / Twitter card
        $title = $desc = $image = $provider = '';
        $title    = self::metaTagValue($html, 'property', 'og:title') ?: self::metaTagValue($html, 'name', 'twitter:title');
        $desc     = self::metaTagValue($html, 'property', 'og:description') ?: self::metaTagValue($html, 'name', 'twitter:description');
        $image    = self::metaTagValue($html, 'property', 'og:image')
                 ?: self::metaTagValue($html, 'property', 'og:image:url')
                 ?: self::metaTagValue($html, 'property', 'og:image:secure_url')
                 ?: self::metaTagValue($html, 'name', 'twitter:image')
                 ?: self::metaTagValue($html, 'name', 'twitter:image:src');
        $provider = self::metaTagValue($html, 'property', 'og:site_name');
        // Fallback: <title>
        if (!$title && preg_match('/<title[^>]*>(.*?)<\/title>/si', $html, $mm)) $title = html_entity_decode(strip_tags($mm[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        if (!$title) return null; // sem título, não vale card
        $title = trim(html_entity_decode($title, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        $desc = trim(html_entity_decode($desc, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        $provider = trim(html_entity_decode($provider, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        $image = trim($image);
        if ($image !== '') {
            $image = absolute_url($finalUrl ?: $url, $image);
        }
        if (self::looksBrokenCard(['title' => $title, 'description' => $desc, 'provider' => $provider, 'image' => $image])) {
            return null;
        }

        // Armazenar pelo URL original (para que lookups futuros pelo mesmo URL encontrem o cache)
        $row = ['url' => $url, 'title' => mb_substr($title, 0, 255), 'description' => mb_substr($desc, 0, 500), 'image' => $image, 'provider' => mb_substr($provider, 0, 100), 'card_type' => 'link', 'share_count' => $increment ? 1 : 0, 'fetched_at' => now_iso()];
        DB::insertIgnore('link_cards', $row);
        if ($normalizedUrl !== $url) {
            DB::insertIgnore('link_cards', array_merge($row, ['url' => $normalizedUrl, 'share_count' => 0]));
        }
        // Também armazenar pelo URL final (para lookups futuros se o URL final chegar direto)
        if ($finalUrl && $finalUrl !== $url && $finalUrl !== $normalizedUrl) {
            // Final URL row is a lookup alias, not an additional share event.
            DB::insertIgnore('link_cards', array_merge($row, ['url' => $finalUrl, 'share_count' => 0]));
        }
        return self::cardObject($row);
    }

    private static function cardObject(array $r): array
    {
        return [
            'url'               => $r['url'],
            'title'             => $r['title'],
            'description'       => $r['description'] ?? '',
            'type'              => $r['card_type'] ?? 'link',
            'author_name'       => '',
            'author_url'        => '',
            'provider_name'     => $r['provider'] ?? '',
            'provider_url'      => '',
            'html'              => '',
            'width'             => 0,
            'height'            => 0,
            'image'             => (($r['image'] ?? '') !== '' ? (absolute_url($r['url'] ?? '', (string)$r['image']) ?: null) : null),
            'image_description' => '',
            'embed_url'         => '',
            'blurhash'          => null,
        ];
    }

}
