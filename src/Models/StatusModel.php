<?php
declare(strict_types=1);

namespace App\Models;

class StatusModel
{
    private static function expiresAtFromInput(array $d): ?string
    {
        if (!empty($d['expires_at'])) {
            $ts = strtotime((string)$d['expires_at']);
            if ($ts !== false && $ts > time()) return gmdate('Y-m-d\TH:i:s\Z', $ts);
        }
        if (array_key_exists('expires_in', $d)) {
            $seconds = (int)$d['expires_in'];
            if ($seconds > 0) return gmdate('Y-m-d\TH:i:s\Z', time() + $seconds);
        }
        return null;
    }

    private static function isExpiredLocalStatus(array $s): bool
    {
        if ((int)($s['local'] ?? 0) !== 1) return false;
        $expiresAt = (string)($s['expires_at'] ?? '');
        return $expiresAt !== '' && strtotime($expiresAt) !== false && strtotime($expiresAt) <= time();
    }

    private static function deleteMediaFilesForStatus(string $statusId, bool $onlyUnowned = false): void
    {
        $rows = DB::all(
            'SELECT ma.id, ma.url, ma.preview_url, ma.status_id
             FROM media_attachments ma
             JOIN status_media sm ON sm.media_id=ma.id
             WHERE sm.status_id=?',
            [$statusId]
        );
        foreach ($rows as $m) {
            if ($onlyUnowned && !empty($m['status_id'])) continue;
            foreach ([$m['url'] ?? '', $m['preview_url'] ?? ''] as $mediaUrl) {
                if (!is_string($mediaUrl) || $mediaUrl === '') continue;
                $path = AP_MEDIA_DIR . '/' . basename(parse_url($mediaUrl, PHP_URL_PATH) ?? $mediaUrl);
                if (is_file($path)) @unlink($path);
            }
        }
    }

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
            if ($key === 'image' && !preg_match('#^https?://#i', $val)) return true;
        }
        return false;
    }

    public static function create(array $d, array $user): array
    {
        $id  = flake_id();
        $now = now_iso();
        $uri = ap_url('objects/' . $id);
        $requestedVisibility = (string)($d['visibility'] ?? 'public');
        $visibility = in_array($requestedVisibility, ['public', 'unlisted', 'private', 'direct'], true)
            ? $requestedVisibility
            : 'public';

        $row = [
            'id'          => $id,
            'uri'         => $uri,
            'user_id'     => $user['id'],
            'reply_to_id' => $d['in_reply_to_id'] ?? null,
            'reply_to_uid'=> null,
            'reblog_of_id'=> null,
            'quote_of_id' => $d['quote_id'] ?? null,
            'content'     => $d['status'] ?? '',
            'cw'          => $d['spoiler_text'] ?? '',
            'visibility'  => $visibility,
            'language'    => $d['language'] ?? 'pt',
            'sensitive'   => (int)bool_val($d['sensitive'] ?? false),
            'local'       => 1,
            'reply_count' => 0,
            'reblog_count'=> 0,
            'favourite_count' => 0,
            'expires_at'  => self::expiresAtFromInput($d),
            'created_at'  => $now,
            'updated_at'  => $now,
        ];

        if ($row['reply_to_id']) {
            $parent = self::byId($row['reply_to_id']);
            if ($parent) {
                $row['reply_to_uid'] = $parent['user_id'];
                DB::run('UPDATE statuses SET reply_count=reply_count+1 WHERE id=?', [$parent['id']]);
            }
        }

        DB::insert('statuses', $row);

        foreach (($d['media_ids'] ?? []) as $i => $mid) {
            $media = DB::one('SELECT id FROM media_attachments WHERE id=? AND user_id=? AND status_id IS NULL', [$mid, $user['id']]);
            if (!$media) continue;
            DB::insertIgnore('status_media', ['status_id' => $id, 'media_id' => $mid, 'position' => $i]);
            DB::update('media_attachments', ['status_id' => $id], 'id=? AND user_id=?', [$mid, $user['id']]);
        }

        foreach (extract_tags($row['content']) as $tag) {
            DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tag, 'created_at' => $now]);
            $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tag]);
            if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $id, 'hashtag_id' => $ht['id']]);
        }

        DB::run('UPDATE users SET status_count=status_count+1 WHERE id=?', [$user['id']]);
        UserModel::invalidateCountSyncCache($user['id']);

        return self::byId($id);
    }

    public static function byId(string $id): ?array
    {
        return DB::one('SELECT * FROM statuses WHERE id=?', [$id]);
    }

    public static function byUri(string $uri): ?array
    {
        $row = DB::one('SELECT * FROM statuses WHERE uri=?', [$uri]);
        if ($row) return $row;

        $parsed = parse_url($uri);
        $host   = strtolower((string)($parsed['host'] ?? ''));
        if ($host === '' || !is_local($host)) return null;

        $path = rawurldecode((string)($parsed['path'] ?? ''));
        if ($path === '') return null;

        if (preg_match('~^/objects/([^/?#]+)$~', $path, $m)) {
            return self::byId($m[1]);
        }
        if (preg_match('~^/@[^/]+/([^/?#]+)$~', $path, $m)) {
            return self::byId($m[1]);
        }

        return null;
    }

    public static function delete(string $id, string $userId): bool
    {
        $s = self::byId($id);
        if (!$s || $s['user_id'] !== $userId) return false;

        // Record tombstone so we can return 410 Gone for future fetches
        if (!empty($s['uri'])) {
            DB::insertIgnore('tombstones', ['uri' => $s['uri'], 'deleted_at' => now_iso()]);
        }

        // Cascade: delete any local reblog statuses pointing at this status
        $reblogRows = DB::all('SELECT id, user_id FROM statuses WHERE reblog_of_id=?', [$id]);
        foreach ($reblogRows as $rb) {
            self::delete($rb['id'], $rb['user_id']);
        }

        if ($s['reply_to_id']) {
            DB::run('UPDATE statuses SET reply_count=MAX(0,reply_count-1) WHERE id=?', [$s['reply_to_id']]);
        }
        // Null-out quote references so posts quoting this one don't break
        DB::run('UPDATE statuses SET quote_of_id=NULL WHERE quote_of_id=?', [$id]);
        PollModel::deleteByStatus($id);
        self::deleteMediaFilesForStatus($id);
        DB::run('DELETE FROM media_attachments WHERE id IN (SELECT media_id FROM status_media WHERE status_id=?)', [$id]);
        DB::delete('status_edits',    'status_id=?', [$id]);
        DB::delete('status_media',    'status_id=?', [$id]);
        DB::delete('status_hashtags', 'status_id=?', [$id]);
        DB::delete('status_pins',     'status_id=?', [$id]);
        DB::delete('favourites',      'status_id=?', [$id]);
        DB::delete('bookmarks',       'status_id=?', [$id]);
        DB::delete('reblogs',         'status_id=?', [$id]);
        DB::delete('reblogs',         'reblog_status_id=?', [$id]);
        DB::delete('notifications',   'status_id=?', [$id]);
        DB::delete('statuses',        'id=?',        [$id]);
        DB::run('UPDATE users SET status_count=MAX(0,status_count-1) WHERE id=?', [$userId]);
        UserModel::invalidateCountSyncCache($userId);
        return true;
    }

    /**
     * Delete a remote-cached status (no ownership check — called by InboxProcessor).
     */
    public static function deleteRemote(string $id): void
    {
        $s = self::byId($id);
        if (!$s) return;
        // Record tombstone so we can return 410 Gone for future fetches
        if (!empty($s['uri'])) {
            DB::insertIgnore('tombstones', ['uri' => $s['uri'], 'deleted_at' => now_iso()]);
        }
        // Cascade reblogs
        $reblogRows = DB::all('SELECT id, user_id FROM statuses WHERE reblog_of_id=?', [$id]);
        foreach ($reblogRows as $rb) {
            self::delete($rb['id'], $rb['user_id']);
        }
        if ($s['reply_to_id']) {
            DB::run('UPDATE statuses SET reply_count=MAX(0,reply_count-1) WHERE id=?', [$s['reply_to_id']]);
        }
        // Null-out quote references so posts quoting this one don't break
        DB::run('UPDATE statuses SET quote_of_id=NULL WHERE quote_of_id=?', [$id]);
        PollModel::deleteByStatus($id);
        DB::delete('status_edits',    'status_id=?', [$id]);
        // Delete remote media_attachments (status_id=NULL, linked only via status_media)
        self::deleteMediaFilesForStatus($id, true);
        DB::run(
            'DELETE FROM media_attachments WHERE status_id IS NULL AND id IN (SELECT media_id FROM status_media WHERE status_id=?)',
            [$id]
        );
        DB::delete('status_media',    'status_id=?', [$id]);
        DB::delete('status_hashtags', 'status_id=?', [$id]);
        DB::delete('status_pins',     'status_id=?', [$id]);
        DB::delete('favourites',      'status_id=?', [$id]);
        DB::delete('bookmarks',       'status_id=?', [$id]);
        DB::delete('reblogs',         'status_id=?', [$id]);
        DB::delete('reblogs',         'reblog_status_id=?', [$id]);
        DB::delete('notifications',   'status_id=?', [$id]);
        DB::delete('statuses',        'id=?',        [$id]);
    }

    // ── Timelines ────────────────────────────────────────────

    public static function publicTimeline(
        int $limit = 20,
        ?string $maxId = null,
        ?string $sinceId = null,
        ?string $viewerId = null,
        ?string $minId = null,
        bool $localOnly = false,
        bool $remoteOnly = false,
        bool $onlyMedia = false
    ): array
    {
        // public timeline = posts públicos locais + remotos.
        // O filtro local=true transforma-o em local timeline; remote=true mostra apenas remotos.
        $blockedDomains = self::blockedDomains();
        $domainFilter   = self::domainBlockSql('s.user_id', $blockedDomains);

        $blockFilter = '';
        $p = [];
        if ($viewerId) {
            $blockFilter  = " AND s.user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)";
            $blockFilter .= " AND s.user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)";
            $p = [$viewerId, $viewerId];
        }

        $scopeFilter = '';
        if ($localOnly && !$remoteOnly) {
            $scopeFilter = ' AND s.local=1';
        } elseif ($remoteOnly && !$localOnly) {
            $scopeFilter = ' AND s.local=0';
        }
        $mediaFilter = $onlyMedia ? ' AND EXISTS (SELECT 1 FROM status_media sm WHERE sm.status_id=s.id)' : '';

        $sql = "SELECT s.* FROM statuses s WHERE s.visibility='public'{$scopeFilter}{$mediaFilter}{$blockFilter}{$domainFilter}";
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$maxId]);
            if (!$ref && ctype_digit($maxId)) {
                $ms  = ((int)$maxId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $maxId];
            }
            if ($ref) {
                $sql .= ' AND (s.created_at < ? OR (s.created_at = ? AND s.id < ?))';
                $p[] = $ref['created_at']; $p[] = $ref['created_at']; $p[] = $ref['id'];
            }
        }
        if ($sinceId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$sinceId]);
            if (!$ref && ctype_digit($sinceId)) {
                $ms  = ((int)$sinceId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $sinceId];
            }
            if ($ref) {
                $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))';
                $p[] = $ref['created_at']; $p[] = $ref['created_at']; $p[] = $ref['id'];
            }
        }
        if ($minId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$minId]);
            if (!$ref && ctype_digit($minId)) {
                $ms  = ((int)$minId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $minId];
            }
            if ($ref) {
                $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))';
                $p[] = $ref['created_at']; $p[] = $ref['created_at']; $p[] = $ref['id'];
            }
        }
        if ($minId) {
            $sql .= ' ORDER BY s.created_at ASC, s.id ASC LIMIT ?';
        } else {
            $sql .= ' ORDER BY s.created_at DESC, s.id DESC LIMIT ?';
        }
        $p[] = $limit;
        return DB::all($sql, $p);
    }

    public static function homeTimeline(string $userId, int $limit = 20, ?string $maxId = null, ?string $sinceId = null, ?string $minId = null): array
    {
        $blockedDomains = self::blockedDomains();
        $domainFilter   = self::domainBlockSql('s.user_id', $blockedDomains);

        $sql = "SELECT s.* FROM statuses s
                WHERE (
                    s.user_id=?
                    OR s.user_id IN (
                        SELECT following_id FROM follows WHERE follower_id=? AND pending=0
                    )
                    OR (
                        s.id IN (
                            SELECT sh.status_id FROM status_hashtags sh
                            JOIN tag_follows tf ON tf.hashtag_id=sh.hashtag_id
                            WHERE tf.user_id=?
                        )
                        AND s.visibility IN ('public','unlisted')
                    )
                )
                AND s.visibility IN ('public','unlisted','private')
                AND s.user_id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                AND s.user_id NOT IN (SELECT target_id FROM mutes  WHERE user_id=?)
                {$domainFilter}";
        $p = [$userId, $userId, $userId, $userId, $userId];

        // Paginação por (created_at, id) — cursor composto evita posts duplicados
        // quando há timestamps iguais.
        // Para flake IDs, o timestamp é extraído mesmo que o status tenha sido apagado
        // (ex: após unreblog) para que a paginação não pare no Ivory.
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$maxId]);
            if (!$ref && ctype_digit($maxId)) {
                $ms     = ((int)$maxId >> 16) + 1262304000000;
                $ref    = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $maxId];
            }
            if ($ref) {
                $sql .= ' AND (s.created_at < ? OR (s.created_at = ? AND s.id < ?))';
                $p[] = $ref['created_at']; $p[] = $ref['created_at']; $p[] = $ref['id'];
            }
        }
        if ($sinceId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$sinceId]);
            if (!$ref && ctype_digit($sinceId)) {
                $ms  = ((int)$sinceId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $sinceId];
            }
            if ($ref) {
                $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))';
                $p[] = $ref['created_at']; $p[] = $ref['created_at']; $p[] = $ref['id'];
            }
        }
        if ($minId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$minId]);
            if (!$ref && ctype_digit($minId)) {
                $ms  = ((int)$minId >> 16) + 1262304000000;
                $ref = ['created_at' => gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000)), 'id' => $minId];
            }
            if ($ref) {
                $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))';
                $p[] = $ref['created_at']; $p[] = $ref['created_at']; $p[] = $ref['id'];
            }
        }

        // min_id = "fill gap" → ASC (do mais antigo para o mais recente)
        // since_id = "o que é novo" → DESC (mais recente primeiro, como Mastodon spec)
        if ($minId) {
            $sql .= ' ORDER BY s.created_at ASC, s.id ASC LIMIT ?';
        } else {
            $sql .= ' ORDER BY s.created_at DESC, s.id DESC LIMIT ?';
        }
        $p[] = $limit;

        return DB::all($sql, $p);
    }

    // ── Mastodon Status serialisation ────────────────────────

    /**
     * Serialise a status row to the Mastodon API format.
     * Works for both local posts and remote posts cached in the DB.
     */
    public static function toMasto(array $s, ?string $viewerId = null): ?array
    {
        if (self::isExpiredLocalStatus($s)) {
            self::delete($s['id'], $s['user_id']);
            return null;
        }

        // Resolve author: local user (UUID) or remote actor (AP URL)
        $account = self::resolveAccount($s['user_id'], $viewerId);
        if (!$account) return null;

        // Batch boolean checks into a single query to reduce N+1
        $rbdCheckId = $s['reblog_of_id'] ?? $s['id'];
        // pinned = has the STATUS AUTHOR pinned it on their profile?
        // Remote statuses: we never cache remote pin lists → null.
        // Local statuses: check status_pins by author (not by viewer).
        $isLocal = (int)($s['local'] ?? 1);

        if ($viewerId) {
            $flags = DB::one(
                'SELECT
                    EXISTS(SELECT 1 FROM favourites  WHERE user_id=? AND status_id=?) AS favd,
                    EXISTS(SELECT 1 FROM reblogs     WHERE user_id=? AND status_id=?) AS rbd,
                    EXISTS(SELECT 1 FROM bookmarks   WHERE user_id=? AND status_id=?) AS bkd,
                    EXISTS(SELECT 1 FROM status_pins WHERE user_id=? AND status_id=?) AS pnd',
                [$viewerId, $s['id'], $viewerId, $rbdCheckId, $viewerId, $s['id'], $s['user_id'], $s['id']]
            );
            $favd = (bool)($flags['favd'] ?? false);
            $rbd  = (bool)($flags['rbd']  ?? false);
            $bkd  = (bool)($flags['bkd']  ?? false);
            $pnd  = $isLocal ? (bool)($flags['pnd'] ?? false) : false;
        } else {
            $favd = $rbd = $bkd = false;
            $pnd  = $isLocal
                ? (bool)DB::one('SELECT 1 FROM status_pins WHERE user_id=? AND status_id=?', [$s['user_id'], $s['id']])
                : false;
        }

        $reblog = null;
        if ($s['reblog_of_id']) {
            $orig = self::byId($s['reblog_of_id']);
            if (!$orig) return null; // original foi apagado ou não foi ainda fetched — filtrar da timeline
            $reblog = self::toMasto($orig, $viewerId);
            if (!$reblog) return null; // original não tem author resolvível
        }

        $quoteId          = $s['quote_of_id'] ?? null;
        $quote            = null;
        $quotedRaw        = null; // raw DB row of directly referenced status (for URI stripping)

        // Lazy retroactive resolution: posts cached before the inbox fix may have
        // quote_of_id = null even though they contain a fallback "RE:" / "QT:" link.
        // Look up the quoted URI in local DB only (no HTTP request).
        // On success, persist quote_of_id so future requests skip this block.
        if (!$quoteId && empty($s['local']) && !empty($s['content']) && (
            str_contains($s['content'], 'RE: ') || str_contains($s['content'], 'QT: ') ||
            str_contains($s['content'], 'quote-inline')
        )) {
            $rqUri = null;
            if (preg_match('~<span[^>]*class="quote-inline"[^>]*>.*?href="([^"]+)"~is', $s['content'], $rqm)) {
                $rqUri = $rqm[1];
            } elseif (preg_match('~<p>\s*(?:RE|QT):\s*<a[^>]+href="([^"]+)"~i', $s['content'], $rqm)) {
                $rqUri = $rqm[1];
            }
            if ($rqUri) {
                $rqStatus = self::byUri($rqUri);
                if ($rqStatus) {
                    $quoteId = $rqStatus['id'];
                    DB::run(
                        'UPDATE statuses SET quote_of_id=? WHERE id=? AND quote_of_id IS NULL',
                        [$quoteId, $s['id']]
                    );
                }
            }
        }

        if ($quoteId) {
            $quotedRaw = self::byId($quoteId);
            if ($quotedRaw) {
                // If the directly-quoted status is a reblog (boost), resolve to the
                // original post for display — reblogs have empty content and Ivory
                // would show "Quoted post from X" with no text otherwise.
                $effectiveQuoted = $quotedRaw;
                if (!empty($quotedRaw['reblog_of_id'])) {
                    $orig = self::byId($quotedRaw['reblog_of_id']);
                    if ($orig) $effectiveQuoted = $orig;
                }
                // Only embed the quote if the viewer can actually see the quoted post
                if (self::canView($effectiveQuoted, $viewerId)) {
                    $quote = self::toMasto($effectiveQuoted, $viewerId);
                }
            }
        }

        // If we have a resolved quote, strip "RE: url" / "QT: url" from the content
        // so Ivory doesn't show the link twice (once as text, once as embedded quote card).
        // Use $effectiveQuoted URI (same resolution path that Builder::note uses), so when
        // quote_of_id points to a boost wrapper, we match the original post's URI (not the boost's).
        $stripQuotePattern = $quote && isset($effectiveQuoted)
            ? ($effectiveQuoted['uri'] ?? null)
            : null;

        $media = DB::all(
            'SELECT ma.* FROM media_attachments ma JOIN status_media sm ON sm.media_id=ma.id WHERE sm.status_id=? ORDER BY sm.position',
            [$s['id']]
        );

        $tags = DB::all(
            'SELECT h.id, h.name FROM hashtags h JOIN status_hashtags sh ON sh.hashtag_id=h.id WHERE sh.status_id=?',
            [$s['id']]
        );

        $rawContent = $s['content'] ?? '';

        // Build mentions list from content
        $mentions = self::buildMentions($rawContent);

        // edited_at: only set if updated_at differs from created_at
        $editedAt = ($s['updated_at'] && $s['updated_at'] !== $s['created_at']) ? $s['updated_at'] : null;

        // Content: remote posts already contain HTML; local posts need conversion
        $content = $isLocal
            ? text_to_html($rawContent)
            : ensure_html($rawContent);

        // Strip "RE: <url>" / "QT: <url>" appended by remote servers when we have the quote embedded
        if ($stripQuotePattern) {
            $qUrl = preg_quote($stripQuotePattern, '~');

            // 1. Mastodon 4.3+ format: <span class="quote-inline"><br/> QT: <a ... href="URI">…</a></span>
            $content = preg_replace(
                '~\s*<span[^>]*class="quote-inline"[^>]*>.*?<a[^>]+href="' . $qUrl . '"[^>]*>.*?</a>.*?</span>~is',
                '',
                $content
            );

            // 2. Plain <p> wrapping with href-based anchor (any anchor text)
            $content = preg_replace(
                '~\s*<p>\s*(?:RE|QT):\s*<a[^>]+href="' . $qUrl . '"[^>]*>.*?</a>\s*</p>~is',
                '',
                $content
            );

            // 3. Legacy format where URI also appears as the anchor text
            $content = preg_replace(
                '~\s*<p>\s*(?:RE|QT):\s*<a[^>]*>\s*' . $qUrl . '\s*</a>\s*</p>~i',
                '',
                $content
            );

            // 4. Plain-text "RE: url" / "QT: url" (non-HTML fallback)
            $content = preg_replace(
                '~\s*(?:RE|QT):\s*' . $qUrl . '\s*~i',
                '',
                $content
            );

            $content = trim($content);
        }

        $poll = PollModel::byStatusId($s['id']);

        return [
            'id'                     => $s['id'],
            'created_at'             => best_iso_timestamp($s['created_at'] ?? null, $s['updated_at'] ?? null, $s['id'] ?? null),
            'in_reply_to_id'         => self::resolveStatusId($s['reply_to_id']),
            'in_reply_to_account_id' => self::resolveAccountId($s['reply_to_uid']),
            'sensitive'              => (bool)$s['sensitive'],
            'spoiler_text'           => $s['cw'] ?? '',
            'visibility'             => $s['visibility'],
            'language'               => $s['language'] ?? null,
            'uri'                    => $s['uri'],
            'url'                    => $isLocal ? self::statusWebUrl($s) : $s['uri'],
            'replies_count'          => (int)$s['reply_count'],
            'reblogs_count'          => (int)$s['reblog_count'],
            'favourites_count'       => (int)$s['favourite_count'],
            'quotes_count'           => 0,
            'edited_at'              => $editedAt ? (iso_z($editedAt) ?? best_iso_timestamp($s['updated_at'] ?? null, $s['created_at'] ?? null, $s['id'] ?? null)) : null,
            'expires_at'             => iso_z($s['expires_at'] ?? null),
            'content'                => $content,
            'text'                   => ($isLocal && $viewerId === $s['user_id']) ? ($s['content'] ?? null) : null,
            'reblog'                 => $reblog,
            'application'            => ($isLocal && !$s['reblog_of_id']) ? ['name' => AP_NAME, 'website' => AP_BASE_URL] : null,
            'account'                => $account,
            'media_attachments'      => array_map([MediaModel::class, 'toMasto'], $media),
            'mentions'               => $mentions,
            'tags'                   => array_map(fn($t) => ['id' => $t['id'], 'name' => $t['name'], 'url' => ap_url('tags/' . rawurlencode($t['name']))], $tags),
            'emojis'                 => [],
            'card'                   => self::getCard($rawContent, $s['uri']),
            'poll'                   => $poll ? PollModel::toMasto($poll, $viewerId) : null,
            'quote_id'               => $quote ? $quote['id'] : null,
            'quote'                  => $quote,
            'favourited'             => (bool)$favd,
            'reblogged'              => (bool)$rbd,
            'muted'                  => false,
            'bookmarked'             => (bool)$bkd,
            'pinned'                 => $pnd,
            'filtered'               => [],
        ];
    }

    // ── Private helpers ──────────────────────────────────────

    /**
     * Resolve reply_to_id to a local status UUID.
     * If it's already a UUID → return as-is.
     * If it's a remote URI → try to find the cached status and return its UUID.
     * If not found → return null (avoids sending non-ID strings to clients).
     */
    private static function resolveStatusId(?string $replyToId): ?string
    {
        if (!$replyToId) return null;
        // Local UUID (no http prefix)
        if (!str_starts_with($replyToId, 'http')) return $replyToId;
        // Remote URI — try to find locally cached status
        $s = self::byUri($replyToId);
        return $s ? $s['id'] : null;
    }

    /**
     * Resolve a user_id or reply_to_uid to the correct Mastodon account ID.
     * Local UUIDs are returned as-is; remote AP URLs are mapped to masto_id.
     */
    private static function resolveAccountId(?string $userId): ?string
    {
        if (!$userId) return null;
        // Local UUID (no http prefix)
        if (!str_starts_with($userId, 'http')) return $userId;
        // Remote AP URL — return masto_id (md5 of AP URL)
        $ra = DB::one('SELECT masto_id FROM remote_actors WHERE id=?', [$userId]);
        return $ra ? $ra['masto_id'] : null;
    }

    /**
     * Build the web-facing URL for a local status (used as the `url` field in Mastodon API).
     * Format: https://domain/@username/:id
     */
    private static function statusWebUrl(array $s): string
    {
        $user = UserModel::byId($s['user_id']);
        if ($user) return ap_url('@' . $user['username'] . '/' . $s['id']);
        return $s['uri'];
    }

    /**
     * Resolve a user_id (local UUID or remote AP URL) to a Mastodon account array.
     */
    private static function resolveAccount(string $userId, ?string $viewerId): ?array
    {
        // Local user: UUID format
        $local = UserModel::byId($userId);
        if ($local) return UserModel::toMasto($local, $viewerId);

        // Remote actor: user_id is an AP URL
        $remote = DB::one('SELECT * FROM remote_actors WHERE id=?', [$userId]);
        if ($remote) {
            // Lazy refresh: if counts are zero and record is stale, refresh once per actor
            // per request (static cache prevents duplicate HTTP calls for the same actor).
            static $refreshed = [];
            if (!isset($refreshed[$userId])
                && (int)$remote['follower_count'] === 0
                && (int)$remote['following_count'] === 0
                && time() - (int)strtotime($remote['fetched_at']) > 3600
            ) {
                $refreshed[$userId] = true;
                // Defer the HTTP fetch so it runs after the response is sent, preventing
                // a 10-second blocking wait during timeline/status serialisation.
                defer_after_response(function () use ($userId) {
                    if (throttle_allow('remote_actor_refresh:' . $userId, 1800)) {
                        \App\Models\RemoteActorModel::fetch($userId, true);
                    }
                });
            }
            return UserModel::remoteToMasto($remote);
        }

        // Fallback stub — prevents boosts/posts from being silently dropped when the
        // remote actor isn't cached yet. The actor will be properly fetched on next
        // inbox activity. Avatar/header use safe placeholder URLs so Swift clients
        // (Ivory, IceCubes) can decode the URL fields without errors.
        if (str_starts_with($userId, 'http')) {
            $base   = AP_BASE_URL;
            $domain = parse_url($userId, PHP_URL_HOST) ?? 'unknown';
            $uname  = ltrim((string)(basename(parse_url($userId, PHP_URL_PATH) ?? '') ?: 'unknown'), '@');
            return [
                'id'              => md5($userId),
                'username'        => $uname,
                'acct'            => "$uname@$domain",
                'display_name'    => $uname,
                'locked'          => false,
                'bot'             => false,
                'created_at'      => now_iso(),
                'note'            => '',
                'url'             => $userId,
                'uri'             => $userId,
                'avatar'          => $base . '/img/avatar.svg',
                'avatar_static'   => $base . '/img/avatar.svg',
                'header'          => $base . '/img/header.svg',
                'header_static'   => $base . '/img/header.svg',
                'followers_count' => 0,
                'following_count' => 0,
                'statuses_count'  => 0,
                'last_status_at'  => null,
                'emojis'          => [],
                'fields'          => [],
                'roles'           => [],
                'group'           => false,
                'discoverable'    => false,
                'noindex'         => false,
                'suspended'       => false,
                'limited'         => false,
                'moved'           => null,
                'also_known_as'   => [],
            ];
        }

        return null;
    }

    /**
     * Return a cached link card for the first URL in the content, or null.
     * Live fetching is handled by StatusesCtrl::card() — this only reads cache.
     */
    private static function getCard(string $rawContent, string $statusUri): ?array
    {
        if (!preg_match('~https?://[^\s<>"\')\]]+~', $rawContent, $m)) return null;
        $url    = rtrim($m[0], '.,;:');
        $lookup = normalize_http_url($url);
        $cached = DB::one('SELECT * FROM link_cards WHERE url=?', [$url])
               ?? DB::one('SELECT * FROM link_cards WHERE url=?', [$lookup]);
        if (!$cached || !$cached['title'] || self::looksBrokenCard($cached)) return null;
        return [
            'url'               => $cached['url'],
            'title'             => $cached['title'],
            'description'       => $cached['description'] ?? '',
            'type'              => $cached['card_type'] ?? 'link',
            'author_name'       => '',
            'author_url'        => '',
            'provider_name'     => $cached['provider'] ?? '',
            'provider_url'      => '',
            'html'              => '',
            'width'             => 0,
            'height'            => 0,
            'image'             => (($cached['image'] ?? '') !== '' ? (absolute_url($cached['url'] ?? $url, (string)$cached['image']) ?: null) : null),
            'image_description' => '',
            'embed_url'         => '',
            'blurhash'          => null,
        ];
    }

    /**
     * Build the mentions array for a status by parsing content.
     * For HTML content (remote posts): extract from <a class="mention" href="...">.
     * For plain text (local posts): use @user@domain regex.
     */
    private static function buildMentions(string $content): array
    {
        $out  = [];
        $seen = [];
        $seenKey = static fn(string $scope, string $id): string => $scope . ':' . $id;

        // HTML content: extract mentions from <a class="mention" href="...">
        if ($content !== strip_tags($content)) {
            if (preg_match_all('/<a\s[^>]*href=["\']([^"\']+)["\'][^>]*class="[^"]*mention[^"]*"[^>]*>|<a\s[^>]*class="[^"]*mention[^"]*"[^>]*href=["\']([^"\']+)["\'][^>]*>/i', $content, $hms, PREG_SET_ORDER)) {
                foreach ($hms as $hm) {
                    $href = $hm[1] ?: $hm[2];
                    if (!$href || !str_starts_with($href, 'http')) continue;
                    $domain = parse_url($href, PHP_URL_HOST) ?? '';
                    $path   = parse_url($href, PHP_URL_PATH) ?? '';
                    // Strip leading @ — profile URLs use /@username format; AP URLs use /users/username
                    $uname  = ltrim(basename($path), '@');
                    if (!$uname || !$domain) continue;

                    if (is_local($domain)) {
                        $u = UserModel::byUsername($uname);
                        if ($u) {
                            $key = $seenKey('local', $u['id']);
                            if (isset($seen[$key])) continue;
                            $seen[$key] = true;
                            $out[] = ['id' => $u['id'], 'username' => $u['username'], 'acct' => $u['username'], 'url' => ap_url('@' . $u['username'])];
                        }
                    } else {
                        $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$href])
                           ?? DB::one('SELECT * FROM remote_actors WHERE username=? AND domain=?', [$uname, $domain]);
                        if ($ra) {
                            $key = $seenKey('remote', $ra['id']);
                            if (isset($seen[$key])) continue;
                            $seen[$key] = true;
                            $out[] = ['id' => $ra['masto_id'] ?: md5($ra['id']), 'username' => $ra['username'], 'acct' => $ra['username'] . '@' . $ra['domain'], 'url' => ($ra['url'] ?: $ra['id'])];
                        }
                    }
                }
            }
        }

        // Text-based extraction (for local posts + fallback for remote posts without proper anchor classes)
        // Strip HTML tags before regex extraction to avoid false positives from href attributes
        $textForMentions = $content !== strip_tags($content) ? strip_tags($content) : $content;
        foreach (extract_mentions($textForMentions) as $m) {
            if ($m['remote']) {
                $ra = DB::one('SELECT * FROM remote_actors WHERE username=? AND domain=?', [$m['username'], $m['domain']]);
                if ($ra) {
                    $key = $seenKey('remote', $ra['id']);
                    if (isset($seen[$key])) continue;
                    $seen[$key] = true;
                    $out[] = ['id' => $ra['masto_id'] ?: md5($ra['id']), 'username' => $ra['username'], 'acct' => $ra['username'] . '@' . $ra['domain'], 'url' => ($ra['url'] ?: $ra['id'])];
                }
            } else {
                $u = UserModel::byUsername($m['username']);
                if ($u) {
                    $key = $seenKey('local', $u['id']);
                    if (isset($seen[$key])) continue;
                    $seen[$key] = true;
                    $out[] = ['id' => $u['id'], 'username' => $u['username'], 'acct' => $u['username'], 'url' => ap_url('@' . $u['username'])];
                }
            }
        }
        return $out;
    }

    /**
     * Check whether a viewer is allowed to see a status.
     * Enforces visibility rules for public/unlisted/private/direct posts.
     */
    public static function canView(array $s, ?string $viewerId): bool
    {
        $v = $s['visibility'] ?? 'public';
        if ($v === 'public' || $v === 'unlisted') return true;
        if (!$viewerId) return false;
        // Author can always see their own posts
        if ($viewerId === $s['user_id']) return true;
        if ($v === 'private') {
            return (bool)DB::one(
                'SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=0',
                [$viewerId, $s['user_id']]
            );
        }
        if ($v === 'direct') {
            // Check via notification record first (fast path)
            if (DB::one(
                "SELECT 1 FROM notifications WHERE status_id=? AND user_id=? AND type IN ('mention','direct')",
                [$s['id'], $viewerId]
            )) return true;
            // Fallback: inspect parsed mentions so access survives notification dismissal
            foreach (self::buildMentions($s['content'] ?? '') as $mention) {
                if (($mention['id'] ?? null) === $viewerId) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    public static function deleteExpiredLocal(int $limit = 25): int
    {
        $rows = DB::all(
            "SELECT id, user_id FROM statuses
             WHERE local=1 AND expires_at IS NOT NULL AND expires_at<>'' AND expires_at<=?
             ORDER BY expires_at ASC LIMIT ?",
            [now_iso(), max(1, $limit)]
        );
        $deleted = 0;
        foreach ($rows as $row) {
            if (self::delete((string)$row['id'], (string)$row['user_id'])) {
                $deleted++;
            }
        }
        return $deleted;
    }

    /**
     * Return list of blocked domains.
     * Cached per-request in a static variable.
     */
    public static function blockedDomains(): array
    {
        static $cache = null;
        if ($cache === null) {
            try {
                $rows  = DB::all('SELECT domain FROM domain_blocks');
                $cache = array_column($rows, 'domain');
            } catch (\Throwable) {
                $cache = [];
            }
        }
        return $cache;
    }

    /**
     * Build a SQL fragment to exclude posts from blocked domains.
     * The user_id column for remote actors is their AP URL (e.g. https://domain/users/alice).
     * Match on the URL prefix "https://domain/" to avoid false positives from substring matches
     * (e.g. blocking "foo.com" must NOT also block "notfoo.com").
     */
    public static function domainBlockSql(string $col, array $domains): string
    {
        if (!$domains) return '';
        $pdo = DB::pdo();
        $clauses = array_map(function($d) use ($col, $pdo) {
            $escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $d);
            $https   = $pdo->quote('https://' . $escaped . '/%');
            $http    = $pdo->quote('http://'  . $escaped . '/%');
            return " AND $col NOT LIKE $https ESCAPE '\\'"
                 . " AND $col NOT LIKE $http  ESCAPE '\\'";
        }, $domains);
        return implode('', $clauses);
    }
}
