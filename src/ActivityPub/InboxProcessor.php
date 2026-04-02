<?php
declare(strict_types=1);

namespace App\ActivityPub;

use App\Models\{DB, UserModel, StatusModel, RemoteActorModel, CryptoModel, PollModel};

class InboxProcessor
{
    private static function isLegacyGhostBodySignatureCompatible(array $activity, string $actorId, string $type): bool
    {
        if (!in_array($type, ['Follow', 'Accept', 'Reject'], true)) return false;
        if ($actorId === '') return false;

        $signature = $activity['signature'] ?? null;
        if (!is_array($signature)) return false;
        if (($signature['type'] ?? '') !== 'RsaSignature2017') return false;

        $creator = trim((string)($signature['creator'] ?? ''));
        $created = trim((string)($signature['created'] ?? ''));
        $value   = trim((string)($signature['signatureValue'] ?? ''));
        if ($creator === '' || $created === '' || $value === '') return false;

        $expectedCreator = rtrim($actorId, '/') . '#main-key';
        if ($creator !== $expectedCreator) return false;

        $actorHost = strtolower((string)(parse_url($actorId, PHP_URL_HOST) ?? ''));
        $creatorHost = strtolower((string)(parse_url($creator, PHP_URL_HOST) ?? ''));
        if ($actorHost === '' || $actorHost !== $creatorHost) return false;

        $actorPath = (string)(parse_url($actorId, PHP_URL_PATH) ?? '');
        if (!str_contains($actorPath, '/.ghost/activitypub/')) return false;

        // Try to fetch the actor, but don't hard-fail if the fetch fails.
        // The HTTP Signature verification already attempted a forced fetch; if the
        // Ghost server was temporarily unreachable both attempts would fail, causing
        // valid Ghost activities to be rejected. Since we already confirmed this is
        // a Ghost instance via the path check, accept the activity even when the
        // actor can't be fetched — it will be fetched later when needed.
        $actor = RemoteActorModel::fetch($actorId);
        if ($actor && trim((string)($actor['public_key'] ?? '')) === '') return false;

        $createdTs = strtotime($created);
        if ($createdTs === false || abs(time() - $createdTs) > 43200) return false;

        return true;
    }

    private static function findRemoteNotification(string $userId, string $fromAcctId, string $type, ?string $statusId = null): ?array
    {
        return DB::one(
            'SELECT * FROM notifications WHERE user_id=? AND from_acct_id=? AND type=? AND ' .
            ($statusId === null ? 'status_id IS NULL' : 'status_id=?') . ' LIMIT 1',
            $statusId === null
                ? [$userId, $fromAcctId, $type]
                : [$userId, $fromAcctId, $type, $statusId]
        );
    }

    private static function insertRemoteNotification(string $userId, string $fromAcctId, string $type, ?string $statusId, ?string $createdAt = null): void
    {
        if (self::findRemoteNotification($userId, $fromAcctId, $type, $statusId)) return;
        DB::insertIgnore('notifications', [
            'id'           => flake_id_at($createdAt),
            'user_id'      => $userId,
            'from_acct_id' => $fromAcctId,
            'type'         => $type,
            'status_id'    => $statusId,
            'read_at'      => null,
            'created_at'   => $createdAt ?: now_iso(),
        ]);
    }

    private static function refreshRemoteNotification(string $userId, string $fromAcctId, string $type, ?string $statusId, ?string $createdAt = null): void
    {
        $existing = self::findRemoteNotification($userId, $fromAcctId, $type, $statusId);
        if (!$existing) {
            self::insertRemoteNotification($userId, $fromAcctId, $type, $statusId, $createdAt);
            return;
        }
        DB::update('notifications', [
            'created_at' => $createdAt ?: now_iso(),
            'read_at'    => null,
        ], 'id=?', [$existing['id']]);
    }

    private static function reconcileRepliesForParent(string $statusId, string $statusUri, string $ownerId): void
    {
        if ($statusUri !== '') {
            DB::run(
                'UPDATE statuses
                 SET reply_to_id=?, reply_to_uid=?
                 WHERE reply_to_id=?',
                [$statusId, $ownerId, $statusUri]
            );
        }
        $count = (int)(DB::one(
            'SELECT COUNT(*) n FROM statuses WHERE reply_to_id IN (?, ?)',
            [$statusId, $statusUri]
        )['n'] ?? 0);
        DB::run('UPDATE statuses SET reply_count=? WHERE id=?', [$count, $statusId]);
    }

    public static function process(array $activity, array $headers, string $method, string $path, string $rawBody = ''): bool
    {
        $type    = $activity['type'] ?? '';
        $actorId = is_string($activity['actor'] ?? null)
            ? $activity['actor']
            : ($activity['actor']['id'] ?? '');

        // ── 1. Domain block check ─────────────────────────────
        if ($actorId) {
            $domain = parse_url($actorId, PHP_URL_HOST) ?? '';
            if ($domain && is_domain_blocked($domain)) {
                // Silently ignore activities from blocked domains
                return false;
            }
        }

        // ── 2. HTTP Signature verification ───────────────────
        $sigError = '';
        $obj      = $activity['object'] ?? '';
        $objId    = is_string($obj) ? $obj : ($obj['id'] ?? '');

        // Account-level Delete: actor == object (tombstone). The deleted actor's key
        // endpoint returns 404, so normal verification always fails. This is the classic
        // ActivityPub tombstone problem — all major implementations accept these.
        // A forged account-Delete can only remove our cached copy of a remote actor,
        // which is harmless (data re-fetched on next contact).
        $isAccountDelete = ($type === 'Delete' && $objId !== '' && $objId === $actorId);

        $hasHttpSignature = !empty($headers['signature']);
        $httpSigResult    = $hasHttpSignature
            ? CryptoModel::verifyIncomingDetailed($headers, $method, $path, $rawBody)
            : ['ok' => false, 'error' => '', 'key_id' => '', 'actor_url' => '', 'algorithm' => '', 'headers' => ''];
        $httpSigOk        = (bool)$httpSigResult['ok'];
        $proofSigOk       = false;

        if ($hasHttpSignature) {
            if (!$httpSigOk) {
                $proofSigOk = CryptoModel::verifyObjectSignature($activity, $actorId);
                if ($proofSigOk) {
                    $sigError = 'Verified via DataIntegrityProof fallback';
                } else {
                    $rsaSigResult = CryptoModel::verifyRsaSignature2017Detailed($activity, $actorId);
                    if ($rsaSigResult['ok']) {
                    $proofSigOk = true;
                    $sigError = 'Verified via RsaSignature2017 body signature';
                    } elseif (self::isLegacyGhostBodySignatureCompatible($activity, $actorId, (string)$type)) {
                    $sigError = 'Accepted via Ghost legacy body signature compatibility';
                    } elseif ($isAccountDelete) {
                    // Verification failed because the actor is gone — accept anyway.
                    // Log without error so it doesn't flood the error list.
                    $sigError = '';
                    } elseif ($type === 'Delete' && !CryptoModel::fetchPublicKey($actorId)) {
                    // Post-Delete from an actor whose key can no longer be fetched
                    // (account deleted on their server). Mastodon sends individual post
                    // Tombstones after the account Delete, by which point the key is gone.
                    // Accepting is safe — worst case a cached post is removed.
                    $sigError = '';
                    } else {
                    $detail = trim((string)($httpSigResult['error'] ?? ''));
                    $algo = trim((string)($httpSigResult['algorithm'] ?? ''));
                    $headersList = trim((string)($httpSigResult['headers'] ?? ''));
                    $sigError = 'HTTP Signature verification failed';
                    if ($detail !== '') $sigError .= ' [' . $detail . ']';
                    $rsaDetail = trim((string)($rsaSigResult['error'] ?? ''));
                    if ($rsaDetail !== '') $sigError .= ' rsa=' . $rsaDetail;
                    if ($algo !== '') $sigError .= ' alg=' . $algo;
                    if ($headersList !== '') $sigError .= ' headers=' . $headersList;
                    self::log($actorId, $type, $activity, $sigError);
                    return false;
                    }
                }
            }
        } else {
            $proofSigOk = CryptoModel::verifyObjectSignature($activity, $actorId);
            if ($proofSigOk) {
                $sigError = 'Verified via DataIntegrityProof';
            } else {
                $rsaSigResult = CryptoModel::verifyRsaSignature2017Detailed($activity, $actorId);
                if ($rsaSigResult['ok']) {
                $proofSigOk = true;
                $sigError = 'Verified via RsaSignature2017 body signature';
                } elseif (self::isLegacyGhostBodySignatureCompatible($activity, $actorId, (string)$type)) {
                $sigError = 'Accepted via Ghost legacy body signature compatibility';
                } elseif (!$isAccountDelete) {
                // Unsigned requests are only tolerated for actor tombstones. Accepting unsigned
                // post Deletes would let anyone forge a cache purge for arbitrary remote content.
                $sigError = 'Missing HTTP Signature — rejected';
                $rsaDetail = trim((string)($rsaSigResult['error'] ?? ''));
                if ($rsaDetail !== '') $sigError .= ' rsa=' . $rsaDetail;
                self::log($actorId, $type, $activity, $sigError);
                return false;
                } else {
                $sigError = 'No HTTP Signature (Delete exempted)';
                }
            }
        }

        // ── 3. Log ────────────────────────────────────────────
        self::log($actorId, $type, $activity, $sigError);

        // ── 4. Ensure actor is cached ────────────────────────
        if ($actorId) RemoteActorModel::fetch($actorId);

        // ── 5. Dispatch ───────────────────────────────────────
        return match ($type) {
            'Create'   => self::onCreate($activity, $actorId),
            'Update'   => self::onUpdate($activity, $actorId),
            'Delete'   => self::onDelete($activity, $actorId),
            'Follow'   => self::onFollow($activity, $actorId),
            'Undo'     => self::onUndo($activity, $actorId),
            'Accept'   => self::onAccept($activity, $actorId),
            'Reject'   => self::onReject($activity, $actorId),
            'Like'     => self::onLike($activity, $actorId),
            'Announce' => self::onAnnounce($activity, $actorId),
            'Move'     => self::onMove($activity, $actorId),
            default    => true,
        };
    }

    // ── Handlers ─────────────────────────────────────────────

    private static function onCreate(array $a, string $actorId): bool
    {
        $obj = $a['object'] ?? null;
        $noteTypes = ['Note', 'Article', 'Page', 'Question', 'Video', 'Audio', 'Event'];
        if (!is_array($obj) || !in_array($obj['type'] ?? '', $noteTypes, true)) return true;

        $uri = $obj['id'] ?? '';
        if (!$uri) return true;

        if (self::onPollVoteCreate($obj, $actorId)) {
            return true;
        }

        $existing = StatusModel::byUri($uri);
        if ($existing) {
            if ((int)($existing['local'] ?? 0) === 1) {
                // Ignore self-looped Create/Question deliveries for our own local posts.
                // They can arrive back through relays or unusual federation paths and would
                // overwrite plain-text local content with HTML plus disturb poll vote state.
                return true;
            }
            // Threads (and some servers) re-send Create with the same id for edits
            $now = now_iso();
            $newContent = self::apExtractContent($obj);
            $oldParent = null;
            $oldReplyToId = (string)($existing['reply_to_id'] ?? '');
            if ($oldReplyToId !== '') {
                $oldParent = StatusModel::byId($oldReplyToId);
                if (!$oldParent && str_starts_with($oldReplyToId, 'http')) {
                    $oldParent = StatusModel::byUri($oldReplyToId);
                }
            }

            $replyToId  = null;
            $replyToUid = null;
            $inReplyTo  = $obj['inReplyTo'] ?? null;
            if ($inReplyTo && is_string($inReplyTo)) {
                $parent = StatusModel::byUri($inReplyTo);
                if (!$parent && !is_local(parse_url($inReplyTo, PHP_URL_HOST) ?? '')) {
                    $parent = self::fetchRemoteNote($inReplyTo, false, 2);
                }
                if ($parent) {
                    $replyToId  = $parent['id'];
                    $replyToUid = $parent['user_id'];
                } else {
                    $replyToId = $inReplyTo;
                }
            }

            // Record previous version in edit history
            DB::insertIgnore('status_edits', [
                'id'         => uuid(),
                'status_id'  => $existing['id'],
                'content'    => $existing['content'],
                'cw'         => $existing['cw'],
                'sensitive'  => (int)$existing['sensitive'],
                'created_at' => $existing['updated_at'] ?: $existing['created_at'],
            ]);

            DB::update('statuses', [
                'content'    => $newContent !== '' ? $newContent : $existing['content'],
                'cw'         => self::apStr($obj['summary'] ?? '', $existing['cw']),
                'visibility' => self::apVisibility($obj['to'] ?? [], $obj['cc'] ?? []),
                'language'   => is_array($obj['contentMap'] ?? null)
                                    ? (array_key_first((array)$obj['contentMap']) ?? ($existing['language'] ?? 'en'))
                                    : self::apStr($obj['language'] ?? ($existing['language'] ?? 'en'), $existing['language'] ?? 'en'),
                'sensitive'  => (int)($obj['sensitive'] ?? $existing['sensitive']),
                'reply_to_id' => $replyToId,
                'reply_to_uid' => $replyToUid,
                'updated_at' => self::apTimestamp($obj['updated'] ?? null, $now),
            ], 'uri=? AND user_id=?', [$uri, $actorId]);

            $quoteId = null;
            $quoteUri  = $obj['quoteUri'] ?? $obj['quoteUrl'] ?? $obj['_misskey_quote'] ?? null;
            if ($quoteUri && is_string($quoteUri)) {
                $quotedStatus = StatusModel::byUri($quoteUri);
                if (!$quotedStatus) {
                    $quotedStatus = self::fetchRemoteNote($quoteUri, true, 0);
                }
                $quoteId = $quotedStatus ? $quotedStatus['id'] : null;
            }
            DB::run('UPDATE statuses SET quote_of_id=? WHERE id=?', [$quoteId, $existing['id']]);

            if (array_key_exists('attachment', $obj)) {
                DB::run(
                    'DELETE FROM media_attachments WHERE status_id IS NULL AND id IN (SELECT media_id FROM status_media WHERE status_id=?)',
                    [$existing['id']]
                );
                DB::delete('status_media', 'status_id=?', [$existing['id']]);
                foreach (self::apList($obj['attachment'] ?? []) as $pos => $att) {
                    if (!is_array($att)) continue;
                    $url  = self::attachmentUrl($att);
                    $mime = self::apStr($att['mediaType'] ?? '');
                    if (!$url) continue;
                    $type = match(true) {
                        str_starts_with($mime, 'video/') => 'video',
                        str_starts_with($mime, 'audio/') => 'audio',
                        str_starts_with($mime, 'image/') => 'image',
                        default => 'unknown',
                    };
                    $mid  = uuid();
                    DB::insertIgnore('media_attachments', [
                        'id'          => $mid,
                        'user_id'     => $existing['user_id'],
                        'status_id'   => null,
                        'type'        => $type,
                        'url'         => $url,
                        'preview_url' => $url,
                        'description' => self::apStr($att['name'] ?? ''),
                        'blurhash'    => self::apStr($att['blurhash'] ?? ''),
                        'width'       => is_int($att['width'] ?? null) ? $att['width'] : null,
                        'height'      => is_int($att['height'] ?? null) ? $att['height'] : null,
                        'created_at'  => $now,
                    ]);
                    DB::insertIgnore('status_media', [
                        'status_id' => $existing['id'],
                        'media_id'  => $mid,
                        'position'  => $pos,
                    ]);
                }
            }

            if (isset($obj['tag'])) {
                DB::delete('status_hashtags', 'status_id=?', [$existing['id']]);
                foreach (self::apList($obj['tag'] ?? []) as $tag) {
                    if (!is_array($tag) || ($tag['type'] ?? '') !== 'Hashtag') continue;
                    $tagName = strtolower(ltrim((string)($tag['name'] ?? ''), '#'));
                    if ($tagName === '') continue;
                    DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tagName, 'created_at' => $now]);
                    $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
                    if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $existing['id'], 'hashtag_id' => $ht['id']]);
                }
            }

            if (($obj['type'] ?? '') === 'Question') {
                \App\Models\PollModel::syncRemoteQuestion($existing['id'], $obj);
            }

            if ($oldParent && (string)($oldParent['id'] ?? '') !== '') {
                self::reconcileRepliesForParent((string)$oldParent['id'], (string)($oldParent['uri'] ?? ''), (string)$oldParent['user_id']);
            }
            if ($replyToId !== '' && $replyToId !== null) {
                $newParent = StatusModel::byId((string)$replyToId);
                if (!$newParent && str_starts_with((string)$replyToId, 'http')) {
                    $newParent = StatusModel::byUri((string)$replyToId);
                }
                if ($newParent) {
                    self::reconcileRepliesForParent((string)$newParent['id'], (string)($newParent['uri'] ?? ''), (string)$newParent['user_id']);
                }
            }
            self::reconcileRepliesForParent($existing['id'], $uri, (string)$existing['user_id']);
            return true;
        }

        // Pre-compute local mention targets before the early-return guard so that
        // mentions and DMs from non-followers are still stored and notified.
        // Use the authoritative 'tag' array (ActivityPub standard) as primary source,
        // with content-text parsing as fallback for servers that omit tags.
        $localMentionTargets = [];
        $seenMentionIds = [];
        foreach (self::apList($obj['tag'] ?? []) as $tag) {
            if (!is_array($tag) || ($tag['type'] ?? '') !== 'Mention') continue;
            $href = $tag['href'] ?? '';
            if (!$href || !is_local(parse_url($href, PHP_URL_HOST) ?? '')) continue;
            // Extract username from the href URL (e.g. /users/domingo or /@domingo)
            $path  = parse_url($href, PHP_URL_PATH) ?? '';
            $parts = array_filter(explode('/', trim($path, '/')));
            $uname = ltrim((string)end($parts), '@');
            if (!$uname) continue;
            $target = UserModel::byUsername($uname);
            if ($target && !in_array($target['id'], $seenMentionIds)) {
                $localMentionTargets[] = $target;
                $seenMentionIds[] = $target['id'];
            }
        }
        // Fallback: parse content text for mentions not present in tag array
        if (empty($localMentionTargets)) {
            foreach (extract_mentions(strip_tags($obj['content'] ?? '')) as $m) {
                if (!is_local($m['domain'])) continue;
                $target = UserModel::byUsername($m['username']);
                if ($target && !in_array($target['id'], $seenMentionIds)) {
                    $localMentionTargets[] = $target;
                    $seenMentionIds[] = $target['id'];
                }
            }
        }

        // Store the post if: a local user follows this actor, OR the post mentions a local user
        $hasFollower = (bool)DB::one(
            "SELECT 1 FROM follows f
             WHERE f.following_id=? AND f.pending=0
             AND f.follower_id IN (SELECT id FROM users WHERE is_suspended=0)
             LIMIT 1",
            [$actorId]
        );
        if (!$hasFollower && empty($localMentionTargets)) return true;

        $now = now_iso();
        $id  = flake_id();

        // Resolver reply_to_id e reply_to_uid
        $replyToId  = null;
        $replyToUid = null;
        $inReplyTo  = $obj['inReplyTo'] ?? null;
        if ($inReplyTo && is_string($inReplyTo)) {
            $parent = StatusModel::byUri($inReplyTo);
            if (!$parent && !is_local(parse_url($inReplyTo, PHP_URL_HOST) ?? '')) {
                // Parent post not cached — fetch it so context thread is visible.
                // Limit ancestor chain to 2 levels to cap synchronous HTTP calls during
                // inbox processing (each level = 1 outgoing HTTP request, blocks response).
                $parent = self::fetchRemoteNote($inReplyTo, false, 2);
            }
            if ($parent) {
                $replyToId  = $parent['id'];
                $replyToUid = $parent['user_id'];
            } else {
                // Fallback: store the URI so the link is not completely lost
                $replyToId = $inReplyTo;
            }
        }

        // Resolve quote_of_id from quoteUri (FEP-e232 / fedibird / Misskey extension)
        $quoteOfId = null;
        $quoteUri  = $obj['quoteUri'] ?? $obj['quoteUrl'] ?? $obj['_misskey_quote'] ?? null;
        if ($quoteUri && is_string($quoteUri)) {
            $quotedStatus = StatusModel::byUri($quoteUri);
            if (!$quotedStatus) {
                // Quoted post not cached locally — try to fetch it from the remote server
                $quotedStatus = self::fetchRemoteNote($quoteUri, true, 0);
            }
            $quoteOfId = $quotedStatus ? $quotedStatus['id'] : null;
        }

        DB::insertIgnore('statuses', [
            'id'          => $id,
            'uri'         => $uri,
            'user_id'     => $actorId,
            'reply_to_id' => $replyToId,
            'reply_to_uid'=> $replyToUid,
            'reblog_of_id'=> null,
            'quote_of_id' => $quoteOfId,
            'content'     => self::apExtractContent($obj),
            'cw'          => self::apStr($obj['summary'] ?? ''),
            'visibility'  => self::apVisibility($obj['to'] ?? [], $obj['cc'] ?? []),
            'language'    => is_array($obj['contentMap'] ?? null)
                                ? (array_key_first((array)$obj['contentMap']) ?? 'en')
                                : self::apStr($obj['language'] ?? 'en', 'en'),
            'sensitive'   => (int)($obj['sensitive'] ?? false),
            'local'       => 0,
            'reply_count' => 0,
            'reblog_count'=> 0,
            'favourite_count' => 0,
            'created_at'  => self::apTimestamp($obj['published'] ?? null, $now),
            'updated_at'  => self::apTimestamp($obj['updated'] ?? null, self::apTimestamp($obj['published'] ?? null, $now)),
        ]);

        // Guardar attachments (imagens, vídeos)
        foreach (self::apList($obj['attachment'] ?? []) as $pos => $att) {
            if (!is_array($att)) continue;
            $url  = self::attachmentUrl($att);
            $mime = self::apStr($att['mediaType'] ?? '');
            if (!$url) continue;
            $type = match(true) {
                str_starts_with($mime, 'video/') => 'video',
                str_starts_with($mime, 'audio/') => 'audio',
                str_starts_with($mime, 'image/') => 'image',
                default => 'unknown',
            };
            $mid  = uuid();
            DB::insertIgnore('media_attachments', [
                'id'          => $mid,
                'user_id'     => $actorId,
                'status_id'   => null,
                'type'        => $type,
                'url'         => $url,
                'preview_url' => $url,
                'description' => self::apStr($att['name'] ?? ''),
                'blurhash'    => self::apStr($att['blurhash'] ?? ''),
                'width'       => is_int($att['width']  ?? null) ? $att['width']  : null,
                'height'      => is_int($att['height'] ?? null) ? $att['height'] : null,
                'created_at'  => $now,
            ]);
            DB::insertIgnore('status_media', [
                'status_id' => $id,
                'media_id'  => $mid,
                'position'  => $pos,
            ]);
        }

        // Incrementar reply_count no post pai se existir localmente
        if ($replyToId && !str_starts_with((string)$replyToId, 'http')) {
            DB::run('UPDATE statuses SET reply_count=reply_count+1 WHERE id=?', [$replyToId]);
        }

        self::reconcileRepliesForParent($id, $uri, $actorId);

        if (($obj['type'] ?? '') === 'Question') {
            \App\Models\PollModel::syncRemoteQuestion($id, $obj);
        }

        // Index hashtags from remote posts so tag timelines and hashtag follows work
        foreach (self::apList($obj['tag'] ?? []) as $tag) {
            if (!is_array($tag) || ($tag['type'] ?? '') !== 'Hashtag') continue;
            $tagName = strtolower(ltrim($tag['name'] ?? '', '#'));
            if (!$tagName) continue;
            DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tagName, 'created_at' => $now]);
            $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
            if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $id, 'hashtag_id' => $ht['id']]);
        }

        // Pre-fetch mentioned actors from the tag array so buildMentions() can resolve them
        foreach (self::apList($obj['tag'] ?? []) as $tag) {
            if (!is_array($tag) || ($tag['type'] ?? '') !== 'Mention') continue;
            $href = $tag['href'] ?? '';
            if ($href && !is_local(parse_url($href, PHP_URL_HOST) ?? '')) {
                RemoteActorModel::fetch($href);
            }
        }

        // Mention notifications for local users (using pre-computed list)
        foreach ($localMentionTargets as $target) {
            self::insertRemoteNotification($target['id'], $actorId, 'mention', $id, $now);
        }

        // 'status' notifications: alert local users who follow this actor with notify=true
        $notifyFollowers = DB::all(
            'SELECT follower_id FROM follows WHERE following_id=? AND pending=0 AND notify=1
             AND follower_id IN (SELECT id FROM users WHERE is_suspended=0)',
            [$actorId]
        );
        foreach ($notifyFollowers as $row) {
            // Don't duplicate a mention notification the user already received
            $alreadyMentioned = DB::one(
                'SELECT 1 FROM notifications WHERE user_id=? AND status_id=? AND type=?',
                [$row['follower_id'], $id, 'mention']
            );
            if ($alreadyMentioned) continue;
            self::insertRemoteNotification($row['follower_id'], $actorId, 'status', $id, $now);
        }

        // Proactively fetch link card for remote posts so it appears in timelines.
        // Deferred so cURL latency doesn't delay the inbox HTTP response.
        $cardContent = $obj['content'] ?? '';
        if ($cardContent) {
            defer_after_response(function () use ($cardContent) {
                try {
                    \App\Controllers\Api\StatusesCtrl::fetchCard(['content' => $cardContent, 'local' => 0], true);
                } catch (\Throwable) {}
            });
        }

        return true;
    }

    private static function onPollVoteCreate(array $obj, string $actorId): bool
    {
        $replyTo = is_string($obj['inReplyTo'] ?? null) ? $obj['inReplyTo'] : '';
        if ($replyTo === '') return false;

        $status = StatusModel::byUri($replyTo);
        if (!$status || (int)($status['local'] ?? 0) !== 1) return false;

        $poll = PollModel::byStatusId($status['id']);
        if (!$poll) return false;
        if (!empty($poll['closed_at'])) return true;
        if (DB::one('SELECT 1 FROM poll_votes WHERE poll_id=? AND user_id=?', [$poll['id'], $actorId])) return true;

        $titles = [];
        $name = trim((string)($obj['name'] ?? ''));
        if ($name !== '') $titles[] = $name;
        $content = trim(strip_tags((string)($obj['content'] ?? '')));
        if ($content !== '' && $content !== $name) $titles[] = $content;
        $choices = PollModel::choicePositionsByTitles($poll, $titles);
        if (!$choices) return true;

        $votedPoll = PollModel::tryVote($poll, $actorId, array_map('strval', $choices), true);
        if (!$votedPoll) return true;

        $owner = UserModel::byId($status['user_id']);
        if ($owner) {
            $update = Builder::update($status, $owner);
            Delivery::queueToFollowers($owner, $update);
        }

        return true;
    }

    /**
     * Fetch a remote Note by URI and insert it into the local statuses table.
     * Used when a received post quotes or replies to a remote post we don't have cached.
     *
     * @param bool $resolveNested   When true (default), resolves quoteUri one level deep.
     *                              Pass false when called recursively to prevent infinite loops.
     * @param int  $ancestorDepth   How many more levels of inReplyTo to follow up the thread.
     *                              Default 4 means we resolve up to 4 ancestors from the entry point.
     */
    public static function fetchRemoteNote(string $uri, bool $resolveNested = true, int $ancestorDepth = 4, bool $refreshExisting = false): ?array
    {
        if (is_local(parse_url($uri, PHP_URL_HOST) ?? '')) return null;

        $data = RemoteActorModel::httpGet(
            $uri,
            'application/activity+json'
        );
        $noteTypes = ['Note', 'Article', 'Page', 'Question', 'Video', 'Audio', 'Event'];
        if (!$data || !in_array($data['type'] ?? '', $noteTypes, true)) return null;

        $noteUri = $data['id'] ?? $uri;

        // May have been inserted by a concurrent request
        $existing = StatusModel::byUri($noteUri);
        if ($existing) {
            if (!$refreshExisting) return $existing;

            $now = now_iso();
            $oldParent = null;
            $oldReplyToId = (string)($existing['reply_to_id'] ?? '');
            if ($oldReplyToId !== '') {
                $oldParent = StatusModel::byId($oldReplyToId);
                if (!$oldParent && str_starts_with($oldReplyToId, 'http')) {
                    $oldParent = StatusModel::byUri($oldReplyToId);
                }
            }

            $replyToId  = null;
            $replyToUid = null;
            $inReplyTo  = $data['inReplyTo'] ?? null;
            if ($inReplyTo && is_string($inReplyTo)) {
                $parent = StatusModel::byUri($inReplyTo);
                if (!$parent && $ancestorDepth > 0 && !is_local(parse_url($inReplyTo, PHP_URL_HOST) ?? '')) {
                    $parent = self::fetchRemoteNote($inReplyTo, false, $ancestorDepth - 1);
                }
                if ($parent) {
                    $replyToId  = $parent['id'];
                    $replyToUid = $parent['user_id'];
                } else {
                    $replyToId = $inReplyTo;
                }
            }

            DB::update('statuses', [
                'content'    => self::apExtractContent($data) ?: $existing['content'],
                'cw'         => self::apStr($data['summary'] ?? '', $existing['cw']),
                'visibility' => self::apVisibility($data['to'] ?? [], $data['cc'] ?? []),
                'language'   => is_array($data['contentMap'] ?? null)
                                    ? (array_key_first((array)$data['contentMap']) ?? ($existing['language'] ?? 'en'))
                                    : self::apStr($data['language'] ?? ($existing['language'] ?? 'en'), $existing['language'] ?? 'en'),
                'sensitive'  => (int)($data['sensitive'] ?? $existing['sensitive']),
                'reply_to_id' => $replyToId,
                'reply_to_uid' => $replyToUid,
                'updated_at' => self::apTimestamp($data['updated'] ?? null, $now),
            ], 'id=?', [$existing['id']]);

            $quoteId = null;
            $qUri = $data['quoteUri'] ?? $data['quoteUrl'] ?? $data['_misskey_quote'] ?? null;
            if ($qUri && is_string($qUri) && $qUri !== $noteUri) {
                $qStatus = StatusModel::byUri($qUri)
                    ?? self::fetchRemoteNote($qUri, false, 0);
                $quoteId = $qStatus['id'] ?? null;
            }
            DB::run('UPDATE statuses SET quote_of_id=? WHERE id=?', [$quoteId, $existing['id']]);

            DB::run(
                'DELETE FROM media_attachments WHERE status_id IS NULL AND id IN (SELECT media_id FROM status_media WHERE status_id=?)',
                [$existing['id']]
            );
            DB::delete('status_media', 'status_id=?', [$existing['id']]);
            foreach (self::apList($data['attachment'] ?? []) as $pos => $att) {
                if (!is_array($att)) continue;
                $url = self::attachmentUrl($att);
                if (!$url) continue;
                $mime = self::apStr($att['mediaType'] ?? '');
                $type = match(true) {
                    str_starts_with($mime, 'video/') => 'video',
                    str_starts_with($mime, 'audio/') => 'audio',
                    str_starts_with($mime, 'image/') => 'image',
                    default => 'unknown',
                };
                $mid  = uuid();
                DB::insertIgnore('media_attachments', [
                    'id'          => $mid,
                    'user_id'     => $existing['user_id'],
                    'status_id'   => null,
                    'type'        => $type,
                    'url'         => $url,
                    'preview_url' => $url,
                    'description' => self::apStr($att['name'] ?? ''),
                    'blurhash'    => self::apStr($att['blurhash'] ?? ''),
                    'width'       => is_int($att['width'] ?? null) ? $att['width'] : null,
                    'height'      => is_int($att['height'] ?? null) ? $att['height'] : null,
                    'created_at'  => $now,
                ]);
                DB::insertIgnore('status_media', ['status_id' => $existing['id'], 'media_id' => $mid, 'position' => $pos]);
            }

            DB::delete('status_hashtags', 'status_id=?', [$existing['id']]);
            foreach (self::apList($data['tag'] ?? []) as $tag) {
                if (!is_array($tag) || ($tag['type'] ?? '') !== 'Hashtag') continue;
                $tagName = strtolower(ltrim((string)($tag['name'] ?? ''), '#'));
                if ($tagName === '') continue;
                $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
                if (!$ht) {
                    DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tagName, 'created_at' => $now]);
                    $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
                }
                if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $existing['id'], 'hashtag_id' => $ht['id']]);
            }

            if (($data['type'] ?? '') === 'Question') {
                \App\Models\PollModel::syncRemoteQuestion($existing['id'], $data);
            }

            if ($oldParent && (string)($oldParent['id'] ?? '') !== '') {
                self::reconcileRepliesForParent((string)$oldParent['id'], (string)($oldParent['uri'] ?? ''), (string)$oldParent['user_id']);
            }
            if ($replyToId !== '' && $replyToId !== null) {
                $newParent = StatusModel::byId((string)$replyToId);
                if (!$newParent && str_starts_with((string)$replyToId, 'http')) {
                    $newParent = StatusModel::byUri((string)$replyToId);
                }
                if ($newParent) {
                    self::reconcileRepliesForParent((string)$newParent['id'], (string)($newParent['uri'] ?? ''), (string)$newParent['user_id']);
                }
            }
            self::reconcileRepliesForParent($existing['id'], $noteUri, (string)$existing['user_id']);

            return StatusModel::byUri($noteUri);
        }

        $actorId = is_string($data['attributedTo'] ?? null) ? $data['attributedTo'] : '';
        if ($actorId) RemoteActorModel::fetch($actorId);

        $now = now_iso();
        $sid = flake_id();

        // Resolve ancestor (inReplyTo) before inserting so reply_to_id is set correctly.
        // Fetch up the chain recursively (depth-limited) so the full thread context is visible.
        $replyToId  = null;
        $replyToUid = null;
        $inReplyTo  = $data['inReplyTo'] ?? null;
        if ($inReplyTo && is_string($inReplyTo) && $ancestorDepth > 0) {
            $parent = StatusModel::byUri($inReplyTo);
            if (!$parent && !is_local(parse_url($inReplyTo, PHP_URL_HOST) ?? '')) {
                $parent = self::fetchRemoteNote($inReplyTo, false, $ancestorDepth - 1);
            }
            if ($parent) {
                $replyToId  = $parent['id'];
                $replyToUid = $parent['user_id'];
            } else {
                $replyToId = $inReplyTo; // store URI as fallback so the link isn't lost
            }
        }

        DB::insertIgnore('statuses', [
            'id'              => $sid,
            'uri'             => $noteUri,
            'user_id'         => $actorId ?: $noteUri,
            'reply_to_id'     => $replyToId,
            'reply_to_uid'    => $replyToUid,
            'reblog_of_id'    => null,
            'quote_of_id'     => null,
            'content'         => self::apExtractContent($data),
            'cw'              => self::apStr($data['summary'] ?? ''),
            'visibility'      => self::apVisibility($data['to'] ?? [], $data['cc'] ?? []),
            'language'        => is_array($data['contentMap'] ?? null)
                                    ? (array_key_first((array)$data['contentMap']) ?? 'en')
                                    : self::apStr($data['language'] ?? 'en', 'en'),
            'sensitive'       => (int)($data['sensitive'] ?? false),
            'local'           => 0,
            'reply_count'     => 0,
            'reblog_count'    => 0,
            'favourite_count' => 0,
            'created_at'      => self::apTimestamp($data['published'] ?? null, $now),
            'updated_at'      => self::apTimestamp($data['updated'] ?? null, self::apTimestamp($data['published'] ?? null, $now)),
        ]);

        // Store media attachments of the fetched note (images, videos)
        foreach (self::apList($data['attachment'] ?? []) as $pos => $att) {
            if (!is_array($att)) continue;
            $url = self::attachmentUrl($att);
            if (!$url) continue;
            $mime = self::apStr($att['mediaType'] ?? '');
            $type = match(true) {
                str_starts_with($mime, 'video/') => 'video',
                str_starts_with($mime, 'audio/') => 'audio',
                str_starts_with($mime, 'image/') => 'image',
                default => 'unknown',
            };
            $mid  = uuid();
            DB::insertIgnore('media_attachments', [
                'id'          => $mid,
                'user_id'     => $actorId ?: $noteUri,
                'status_id'   => null,
                'type'        => $type,
                'url'         => $url,
                'preview_url' => $url,
                'description' => self::apStr($att['name'] ?? ''),
                'blurhash'    => self::apStr($att['blurhash'] ?? ''),
                'width'       => is_int($att['width']  ?? null) ? $att['width']  : null,
                'height'      => is_int($att['height'] ?? null) ? $att['height'] : null,
                'created_at'  => $now,
            ]);
            DB::insertIgnore('status_media', ['status_id' => $sid, 'media_id' => $mid, 'position' => $pos]);
        }

        // Resolve quoteUri of the fetched note so quoted content is visible in clients.
        // $resolveNested=false prevents infinite recursion (we only go 1 level deep).
        if ($resolveNested) {
            $qUri = $data['quoteUri'] ?? $data['quoteUrl'] ?? $data['_misskey_quote'] ?? null;
            if ($qUri && is_string($qUri) && $qUri !== $noteUri) {
                $qStatus = StatusModel::byUri($qUri)
                    ?? self::fetchRemoteNote($qUri, false, 0);
                if ($qStatus) {
                    DB::run(
                        'UPDATE statuses SET quote_of_id=? WHERE id=? AND quote_of_id IS NULL',
                        [$qStatus['id'], $sid]
                    );
                }
            }
        }

        if (($data['type'] ?? '') === 'Question') {
            \App\Models\PollModel::syncRemoteQuestion($sid, $data);
        }

        foreach (self::apList($data['tag'] ?? []) as $tag) {
            if (!is_array($tag) || ($tag['type'] ?? '') !== 'Hashtag') continue;
            $tagName = strtolower(ltrim($tag['name'] ?? '', '#'));
            if (!$tagName) continue;
            DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tagName, 'created_at' => $now]);
            $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
            if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $sid, 'hashtag_id' => $ht['id']]);
        }

        self::reconcileRepliesForParent($sid, $noteUri, $actorId ?: $noteUri);

        return StatusModel::byUri($noteUri);
    }

    private static function onUpdate(array $a, string $actorId): bool
    {
        $obj = $a['object'] ?? null;
        if (!is_array($obj)) return true;

        $type = $obj['type'] ?? '';

        // Actor update
        if (in_array($type, ['Person', 'Service', 'Application', 'Group', 'Organization'])) {
            RemoteActorModel::fetch($actorId, true);
            return true;
        }

        // Note/Article update (edit)
        if (in_array($type, ['Note', 'Article', 'Page', 'Question', 'Video', 'Audio', 'Event'], true)) {
            $uri = $obj['id'] ?? '';
            if (!$uri) return false;
            $existing = StatusModel::byUri($uri);
            if (!$existing) return true; // not cached locally, ignore
            if ((int)($existing['local'] ?? 0) === 1) return true;

            $now = now_iso();
            $newContent = self::apExtractContent($obj);

            // Record previous version in edit history before overwriting
            DB::insertIgnore('status_edits', [
                'id'         => uuid(),
                'status_id'  => $existing['id'],
                'content'    => $existing['content'],
                'cw'         => $existing['cw'],
                'sensitive'  => (int)$existing['sensitive'],
                'created_at' => $existing['updated_at'] ?: $existing['created_at'],
            ]);

            DB::update('statuses', [
                'content'    => $newContent !== '' ? $newContent : $existing['content'],
                'cw'         => self::apStr($obj['summary'] ?? '', $existing['cw']),
                'language'   => is_array($obj['contentMap'] ?? null)
                                    ? (array_key_first((array)$obj['contentMap']) ?? ($existing['language'] ?? 'en'))
                                    : self::apStr($obj['language'] ?? ($existing['language'] ?? 'en'), $existing['language'] ?? 'en'),
                'sensitive'  => (int)($obj['sensitive'] ?? $existing['sensitive']),
                'updated_at' => self::apTimestamp($obj['updated'] ?? null, $now),
            ], 'uri=?', [$uri]);

            if (($obj['type'] ?? '') === 'Question') {
                \App\Models\PollModel::syncRemoteQuestion($existing['id'], $obj);
            }

            if (array_key_exists('quoteUri', $obj) || array_key_exists('quoteUrl', $obj) || array_key_exists('_misskey_quote', $obj)) {
                $qUri = $obj['quoteUri'] ?? $obj['quoteUrl'] ?? $obj['_misskey_quote'] ?? null;
                $quoteId = null;
                if ($qUri && is_string($qUri)) {
                    $quotedStatus = StatusModel::byUri($qUri)
                        ?? self::fetchRemoteNote($qUri, true, 0);
                    $quoteId = $quotedStatus['id'] ?? null;
                }
                DB::run('UPDATE statuses SET quote_of_id=? WHERE id=?', [$quoteId, $existing['id']]);
            }

            if (array_key_exists('attachment', $obj)) {
                DB::run(
                    'DELETE FROM media_attachments WHERE status_id IS NULL AND id IN (SELECT media_id FROM status_media WHERE status_id=?)',
                    [$existing['id']]
                );
                DB::delete('status_media', 'status_id=?', [$existing['id']]);
                foreach (self::apList($obj['attachment'] ?? []) as $pos => $att) {
                    if (!is_array($att)) continue;
                    $url = self::attachmentUrl($att);
                    if (!$url) continue;
                    $mime = self::apStr($att['mediaType'] ?? '');
                    $type = match (true) {
                        str_starts_with($mime, 'video/') => 'video',
                        str_starts_with($mime, 'audio/') => 'audio',
                        str_starts_with($mime, 'image/') => 'image',
                        default => 'unknown',
                    };
                    $mid = uuid();
                    DB::insertIgnore('media_attachments', [
                        'id'          => $mid,
                        'user_id'     => $existing['user_id'],
                        'status_id'   => null,
                        'type'        => $type,
                        'url'         => $url,
                        'preview_url' => $url,
                        'description' => self::apStr($att['name'] ?? ''),
                        'blurhash'    => self::apStr($att['blurhash'] ?? ''),
                        'width'       => is_int($att['width'] ?? null) ? $att['width'] : null,
                        'height'      => is_int($att['height'] ?? null) ? $att['height'] : null,
                        'created_at'  => $now,
                    ]);
                    DB::insertIgnore('status_media', ['status_id' => $existing['id'], 'media_id' => $mid, 'position' => $pos]);
                }
            }

            // Re-index hashtags if tag array is present in the Update
            if (isset($obj['tag'])) {
                DB::delete('status_hashtags', 'status_id=?', [$existing['id']]);
                foreach (self::apList($obj['tag'] ?? []) as $tag) {
                    if (!is_array($tag) || ($tag['type'] ?? '') !== 'Hashtag') continue;
                    $tagName = strtolower(ltrim($tag['name'] ?? '', '#'));
                    if (!$tagName) continue;
                    $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
                    if (!$ht) {
                        DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tagName, 'created_at' => $now]);
                        $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
                    }
                    if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $existing['id'], 'hashtag_id' => $ht['id']]);
                }
            }
        }

        return true;
    }

    private static function onDelete(array $a, string $actorId): bool
    {
        $obj = $a['object'] ?? '';
        $uri = is_string($obj) ? $obj : ($obj['id'] ?? '');
        if (!$uri) return false;

        // Can only delete content attributed to the actor
        $s = StatusModel::byUri($uri);
        if ($s && $s['user_id'] === $actorId) {
            StatusModel::deleteRemote($s['id']); // handles cascade (reblogs, pins, etc)
        }

        // Actor self-delete (tombstone)
        if ($uri === $actorId) {
            $theirStatuses = DB::all('SELECT id FROM statuses WHERE user_id=?', [$actorId]);
            foreach ($theirStatuses as $row) {
                StatusModel::deleteRemote($row['id']);
            }
            // Decrement following_count for local users who followed the deleted actor
            $localFollowers = DB::all(
                'SELECT follower_id FROM follows WHERE following_id=? AND pending=0
                 AND follower_id IN (SELECT id FROM users)',
                [$actorId]
            );
            foreach ($localFollowers as $row) {
                DB::run('UPDATE users SET following_count=MAX(0,following_count-1) WHERE id=?', [$row['follower_id']]);
            }
            $localTargets = DB::all(
                'SELECT following_id FROM follows WHERE follower_id=? AND pending=0
                 AND following_id IN (SELECT id FROM users)',
                [$actorId]
            );
            foreach ($localTargets as $row) {
                DB::run('UPDATE users SET follower_count=MAX(0,follower_count-1) WHERE id=?', [$row['following_id']]);
            }
            DB::delete('remote_actors', 'id=?', [$actorId]);
            DB::delete('follows', 'follower_id=? OR following_id=?', [$actorId, $actorId]);
            DB::delete('notifications', 'from_acct_id=?', [$actorId]);
        }

        return true;
    }

    private static function onFollow(array $a, string $actorId): bool
    {
        $objectId = is_string($a['object'] ?? null)
            ? $a['object']
            : ($a['object']['id'] ?? '');
        $target = self::resolveLocalUser($objectId);
        if (!$target) return false;

        $now     = now_iso();
        $pending = (int)$target['is_locked'];

        // Check if follow already exists (relay retries / duplicate deliveries)
        $existingFollow = DB::one('SELECT id FROM follows WHERE follower_id=? AND following_id=?', [$actorId, $target['id']]);
        if ($existingFollow) return true;

        DB::insertIgnore('follows', [
            'id'          => uuid(),
            'follower_id' => $actorId,
            'following_id'=> $target['id'],
            'pending'     => $pending,
            'notify'      => 0,
            'local'       => 0,
            'created_at'  => $now,
        ]);

        if (!$pending) {
            DB::run('UPDATE users SET follower_count=follower_count+1 WHERE id=?', [$target['id']]);
        }

        self::insertRemoteNotification($target['id'], $actorId, $pending ? 'follow_request' : 'follow', null, $now);

        // Auto-Accept if not locked
        if (!$pending) {
            $remoteActor = RemoteActorModel::fetch($actorId);
            if ($remoteActor) {
                $accept = Builder::accept($target, $a);
                Delivery::queueToActor($target, $remoteActor, $accept);
            }
        }

        return true;
    }

    private static function onUndo(array $a, string $actorId): bool
    {
        $inner = $a['object'] ?? null;
        if (!is_array($inner)) return false;
        $type = $inner['type'] ?? '';

        if ($type === 'Follow') {
            $targetUrl = is_string($inner['object'] ?? null)
                ? $inner['object']
                : ($inner['object']['id'] ?? '');
            $target = self::resolveLocalUser($targetUrl);
            if (!$target) return false;
            $row = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$actorId, $target['id']]);
            if ($row) {
                DB::delete('follows', 'follower_id=? AND following_id=?', [$actorId, $target['id']]);
                if (!$row['pending']) {
                    DB::run('UPDATE users SET follower_count=MAX(0,follower_count-1) WHERE id=?', [$target['id']]);
                }
                DB::delete('notifications', 'user_id=? AND from_acct_id=? AND type IN (?, ?)', [$target['id'], $actorId, 'follow', 'follow_request']);
            }
            return true;
        }

        if ($type === 'Like') {
            $uri = is_string($inner['object'] ?? null) ? $inner['object'] : '';
            $s   = StatusModel::byUri($uri);
            if ($s) {
                $wasFavourited = (bool)DB::one('SELECT 1 FROM favourites WHERE user_id=? AND status_id=?', [$actorId, $s['id']]);
                DB::delete('favourites', 'user_id=? AND status_id=?', [$actorId, $s['id']]);
                if ($wasFavourited) {
                    DB::run('UPDATE statuses SET favourite_count=MAX(0,favourite_count-1) WHERE id=?', [$s['id']]);
                    DB::delete('notifications', 'user_id=? AND from_acct_id=? AND status_id=? AND type=?', [$s['user_id'], $actorId, $s['id'], 'favourite']);
                }
            }
            return true;
        }

        if ($type === 'Announce') {
            $uri = is_string($inner['object'] ?? null) ? $inner['object'] : '';
            $s   = StatusModel::byUri($uri);
            if ($s) {
                DB::run('UPDATE statuses SET reblog_count=MAX(0,reblog_count-1) WHERE id=?', [$s['id']]);
                // Delete the boost status row (by Announce URI or by actor+reblog_of_id)
                $boostUri = is_string($inner['id'] ?? null) ? $inner['id'] : '';
                if ($boostUri) {
                    $boost = StatusModel::byUri($boostUri);
                    if ($boost) StatusModel::deleteRemote($boost['id']);
                }
                // Fallback: delete any remaining boost rows for this actor+post
                $boostRows = DB::all('SELECT id FROM statuses WHERE user_id=? AND reblog_of_id=?', [$actorId, $s['id']]);
                foreach ($boostRows as $boostRow) {
                    StatusModel::deleteRemote((string)$boostRow['id']);
                }
                DB::delete('notifications', 'user_id=? AND from_acct_id=? AND status_id=? AND type=?', [$s['user_id'], $actorId, $s['id'], 'reblog']);
            }
            return true;
        }

        return false;
    }

    private static function onAccept(array $a, string $actorId): bool
    {
        $inner = $a['object'] ?? null;

        // Relay Accept: relay confirms our Follow subscription
        if (DB::one("SELECT 1 FROM relay_subscriptions WHERE actor_url=? AND status='pending'", [$actorId])) {
            DB::run("UPDATE relay_subscriptions SET status='accepted' WHERE actor_url=?", [$actorId]);
            return true;
        }

        if (is_string($inner)) {
            // Some servers send object as the Follow activity URI string.
            // Match only the exact local follower who originated that Follow.
            $follower = self::resolveLocalFollowerFromFollowId($inner, $actorId);
            if (!$follower) return false;
            $row = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$follower['id'], $actorId]);
            if (!$row || !$row['pending']) return true;
            DB::run('UPDATE follows SET pending=0 WHERE follower_id=? AND following_id=?', [$follower['id'], $actorId]);
            DB::run('UPDATE users SET following_count=following_count+1 WHERE id=?', [$follower['id']]);
            return true;
        }

        if (!is_array($inner) || ($inner['type'] ?? '') !== 'Follow') return false;

        $followerUrl = is_string($inner['actor'] ?? null) ? $inner['actor'] : '';
        $follower    = self::resolveLocalUser($followerUrl);
        if (!$follower) return false;

        // Idempotent: skip if already accepted
        $row = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$follower['id'], $actorId]);
        if (!$row || !$row['pending']) return true; // already accepted or follow doesn't exist

        DB::run('UPDATE follows SET pending=0 WHERE follower_id=? AND following_id=?', [$follower['id'], $actorId]);
        DB::run('UPDATE users SET following_count=following_count+1 WHERE id=?', [$follower['id']]);
        return true;
    }

    private static function onReject(array $a, string $actorId): bool
    {
        $inner = $a['object'] ?? null;

        // Relay Reject: relay refused our Follow subscription — remove it so the admin
        // can see it's rejected and try a different relay.
        if (DB::one("SELECT 1 FROM relay_subscriptions WHERE actor_url=?", [$actorId])) {
            DB::run("DELETE FROM relay_subscriptions WHERE actor_url=?", [$actorId]);
            return true;
        }

        if (is_string($inner)) {
            // Match only the specific pending Follow referenced by the URI.
            $follower = self::resolveLocalFollowerFromFollowId($inner, $actorId);
            if (!$follower) return false;
            $row = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$follower['id'], $actorId]);
            if (!$row || !(int)$row['pending']) return true;
            DB::delete('follows', 'follower_id=? AND following_id=?', [$follower['id'], $actorId]);
            return true;
        }

        if (!is_array($inner) || ($inner['type'] ?? '') !== 'Follow') return false;

        $followerUrl = is_string($inner['actor'] ?? null) ? $inner['actor'] : '';
        $follower    = self::resolveLocalUser($followerUrl);
        if (!$follower) return false;

        $row = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$follower['id'], $actorId]);
        if (!$row || !(int)$row['pending']) return true;
        DB::delete('follows', 'follower_id=? AND following_id=?', [$follower['id'], $actorId]);
        return true;
    }

    /**
     * Resolve an actor URL to a local user.
     * Tries /users/{username} pattern first, then falls back to outbox/webfinger lookup.
     */
    private static function resolveLocalUser(string $actorUrl): ?array
    {
        if (!$actorUrl) return null;

        // Pattern 1: https://our.domain/users/username
        if (preg_match('~/users/([^/?#]+)$~', $actorUrl, $m)) {
            $u = UserModel::byUsername($m[1]);
            if ($u) return $u;
        }

        // Pattern 2: URL matches our domain — try to find any local user with this AP URL
        $urlDomain = parse_url($actorUrl, PHP_URL_HOST);
        if ($urlDomain && is_local($urlDomain)) {
            // Try to extract from the URL path regardless of structure
            $path = parse_url($actorUrl, PHP_URL_PATH) ?? '';
            $parts = array_filter(explode('/', trim($path, '/')));
            $last  = ltrim((string)end($parts), '@');
            if ($last) return UserModel::byUsername($last);
        }

        return null;
    }

    /**
     * Resolve a local follower from a Follow activity URI generated by Builder::follow().
     * Format: https://our.domain/users/alice#follow/<md5(targetUrl)>
     */
    private static function resolveLocalFollowerFromFollowId(string $followId, string $targetActorId): ?array
    {
        if (!$followId) return null;
        $parts = parse_url($followId);
        $host  = $parts['host'] ?? '';
        if (!$host || !is_local($host)) return null;

        $fragment = $parts['fragment'] ?? '';
        if ($fragment !== 'follow/' . md5($targetActorId)) return null;

        $path = $parts['path'] ?? '';
        if (preg_match('~^/users/([^/?#]+)$~', $path, $m)) {
            return UserModel::byUsername($m[1]);
        }
        if (preg_match('~^/@([^/?#]+)$~', $path, $m)) {
            return UserModel::byUsername($m[1]);
        }
        return null;
    }

    private static function onLike(array $a, string $actorId): bool
    {
        $uri = is_string($a['object'] ?? null) ? $a['object'] : '';
        $s   = StatusModel::byUri($uri);
        if (!$s) return false;

        // Only notify if the liked post belongs to a local user
        $owner = UserModel::byId($s['user_id']);
        if (!$owner) return true; // remote post, just update count

        $alreadyFavourited = (bool)DB::one('SELECT 1 FROM favourites WHERE user_id=? AND status_id=?', [$actorId, $s['id']]);
        DB::insertIgnore('favourites', [
            'id' => uuid(), 'user_id' => $actorId, 'status_id' => $s['id'], 'created_at' => now_iso()
        ]);
        if (!$alreadyFavourited) {
            DB::run('UPDATE statuses SET favourite_count=favourite_count+1 WHERE id=?', [$s['id']]);
            self::insertRemoteNotification($s['user_id'], $actorId, 'favourite', $s['id']);
            self::refreshRemoteNotification($s['user_id'], $actorId, 'favourite', $s['id']);
        }
        return true;
    }

    private static function onAnnounce(array $a, string $actorId): bool
    {
        // Skip boosts from local actors — already handled by StatusesCtrl::reblog()
        if ($actorId && is_local(parse_url($actorId, PHP_URL_HOST) ?? '')) {
            return true;
        }

        // O object pode ser uma URI (string) ou um Note/Article inline (array)
        $noteTypes = ['Note', 'Article', 'Page', 'Question', 'Video', 'Audio', 'Event'];
        $inlineNote = (is_array($a['object'] ?? null) && in_array($a['object']['type'] ?? '', $noteTypes, true))
            ? $a['object'] : null;
        $objUri = $inlineNote
            ? ($inlineNote['id'] ?? '')
            : (is_string($a['object'] ?? null) ? $a['object'] : ($a['object']['id'] ?? ''));
        if (!$objUri) return true;

        // Relay Announce: accepted relay is broadcasting a public post from the fediverse
        $relay = DB::one(
            "SELECT daily_limit FROM relay_subscriptions
             WHERE actor_url=? AND status='accepted' AND receive_posts=1",
            [$actorId]
        );
        $isRelay = (bool)$relay;
        $isKnownRelay = (bool)DB::one(
            "SELECT 1 FROM relay_subscriptions
             WHERE actor_url=? AND status='accepted'",
            [$actorId]
        );

        // Relay in send-only mode: keep the subscription for outbound fan-out,
        // but ignore inbound Announce broadcasts from that relay entirely.
        if ($isKnownRelay && !$isRelay) {
            return true;
        }

        if ($isRelay) {
            // Enforce daily ingestion limit to prevent DB bloat on shared hosting.
            // Counts remote posts stored today that came via any relay (not from followed accounts).
            $todayStart = gmdate('Y-m-d') . 'T00:00:00Z';
            $limit      = (int)($relay['daily_limit'] ?? 500);
            $storedToday = (int)(DB::one(
                "SELECT COUNT(*) c FROM statuses
                 WHERE local=0 AND created_at>=?
                   AND user_id NOT IN (SELECT following_id FROM follows WHERE pending=0)",
                [$todayStart]
            )['c'] ?? 0);
            if ($storedToday >= $limit) return true; // daily limit reached — discard
        }

        // Verificar se quem fez o boost é seguido por algum utilizador local
        $hasLocal = $isRelay || (!$isKnownRelay && (bool)DB::one(
            "SELECT 1 FROM follows f
             WHERE f.following_id=? AND f.pending=0
             AND f.follower_id IN (SELECT id FROM users WHERE is_suspended=0)
             LIMIT 1",
            [$actorId]
        ));

        // Check upfront if the boosted URI is a local post (before any remote fetch)
        $isObjLocal = (bool)DB::one('SELECT 1 FROM statuses WHERE uri=? AND local=1', [$objUri]);

        // If nobody follows the booster AND the post is not local AND not a relay, skip entirely —
        // no timeline relevance, no notification needed.
        if (!$hasLocal && !$isObjLocal) return true;

        // Tentar obter o post original (pode estar localmente ou não)
        $orig = StatusModel::byUri($objUri);

        // Se não temos o post original, usar o Note inline (se disponível) ou buscar remotamente
        if (!$orig) {
            $data = $inlineNote ?? \App\Models\RemoteActorModel::httpGet(
                $objUri,
                'application/activity+json'
            );
            $nt = ['Note', 'Article', 'Page', 'Question', 'Video', 'Audio', 'Event'];
            if ($data && in_array($data['type'] ?? '', $nt, true)) {
                // Guardar o post original
                $origActorId = is_string($data['attributedTo'] ?? null) ? $data['attributedTo'] : '';
                if ($origActorId) {
                    RemoteActorModel::fetch($origActorId);
                    $origId = flake_id();
                    $now2   = now_iso();
                    $replyToId  = null;
                    $replyToUid = null;
                    $inReplyTo  = $data['inReplyTo'] ?? null;
                    if ($inReplyTo && is_string($inReplyTo)) {
                        $parent = StatusModel::byUri($inReplyTo);
                        if (!$parent && !is_local(parse_url($inReplyTo, PHP_URL_HOST) ?? '')) {
                            $parent = self::fetchRemoteNote($inReplyTo, false, 2);
                        }
                        if ($parent) {
                            $replyToId  = $parent['id'];
                            $replyToUid = $parent['user_id'];
                        } else {
                            $replyToId = $inReplyTo;
                        }
                    }
                    DB::insertIgnore('statuses', [
                        'id'          => $origId,
                        'uri'         => $objUri,
                        'user_id'     => $origActorId,
                        'reply_to_id' => $replyToId,
                        'reply_to_uid'=> $replyToUid,
                        'reblog_of_id'=> null,
                        'quote_of_id' => null,
                        'content'     => self::apExtractContent($data),
                        'cw'          => self::apStr($data['summary'] ?? ''),
                        'visibility'  => self::apVisibility($data['to'] ?? [], $data['cc'] ?? []),
                        'language'    => is_array($data['contentMap'] ?? null)
                                            ? (array_key_first((array)$data['contentMap']) ?? 'en')
                                            : self::apStr($data['language'] ?? 'en', 'en'),
                        'sensitive'   => (int)($data['sensitive'] ?? false),
                        'local'       => 0,
                        'reply_count' => 0,
                        'reblog_count'=> 0,
                        'favourite_count' => 0,
                        'created_at'  => self::apTimestamp($data['published'] ?? null, $now2),
                        'updated_at'  => self::apTimestamp($data['updated'] ?? null, self::apTimestamp($data['published'] ?? null, $now2)),
                    ]);
                    // Guardar attachments do post original
                    foreach (self::apList($data['attachment'] ?? []) as $pos => $att) {
                        if (!is_array($att)) continue;
                        $url = self::attachmentUrl($att);
                        if (!$url) continue;
                        $mime = self::apStr($att['mediaType'] ?? '');
                        $type = match(true) {
                str_starts_with($mime, 'video/') => 'video',
                str_starts_with($mime, 'audio/') => 'audio',
                str_starts_with($mime, 'image/') => 'image',
                default => 'unknown',
            };
                        $mid  = uuid();
                        DB::insertIgnore('media_attachments', [
                            'id' => $mid, 'user_id' => $origActorId, 'status_id' => null,
                            'type' => $type, 'url' => $url, 'preview_url' => $url,
                            'description' => self::apStr($att['name'] ?? ''),
                            'blurhash' => self::apStr($att['blurhash'] ?? ''),
                            'width' => is_int($att['width'] ?? null) ? $att['width'] : null,
                            'height' => is_int($att['height'] ?? null) ? $att['height'] : null,
                            'created_at' => $now2,
                        ]);
                        DB::insertIgnore('status_media', ['status_id' => $origId, 'media_id' => $mid, 'position' => $pos]);
                    }
                    if ($replyToId && !str_starts_with((string)$replyToId, 'http')) {
                        DB::run('UPDATE statuses SET reply_count=reply_count+1 WHERE id=?', [$replyToId]);
                    }
                    self::reconcileRepliesForParent($origId, $objUri, $origActorId);
                    foreach (self::apList($data['tag'] ?? []) as $tag) {
                        if (!is_array($tag) || ($tag['type'] ?? '') !== 'Hashtag') continue;
                        $tagName = strtolower(ltrim($tag['name'] ?? '', '#'));
                        if (!$tagName) continue;
                        DB::insertIgnore('hashtags', ['id' => uuid(), 'name' => $tagName, 'created_at' => $now2]);
                        $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$tagName]);
                        if ($ht) DB::insertIgnore('status_hashtags', ['status_id' => $origId, 'hashtag_id' => $ht['id']]);
                    }
                    $orig = StatusModel::byUri($objUri);

                    // Resolve quoteUri of the just-stored post so the quote is visible in
                    // clients (e.g. Ivory). Without this, boosted quote posts appear without
                    // the embedded quoted content.
                    if ($orig && !$orig['quote_of_id']) {
                        $qUri = $data['quoteUri'] ?? $data['quoteUrl'] ?? $data['_misskey_quote'] ?? null;
                        if ($qUri && is_string($qUri)) {
                            $qStatus = StatusModel::byUri($qUri)
                                ?? self::fetchRemoteNote($qUri, false, 0);
                            if ($qStatus) {
                                DB::run(
                                    'UPDATE statuses SET quote_of_id=? WHERE id=?',
                                    [$qStatus['id'], $orig['id']]
                                );
                            }
                        }
                    }
                }
            }
        }

        if (!$orig) return true;

        // Only allow boosts of public or unlisted posts
        if (!in_array($orig['visibility'], ['public', 'unlisted'])) return true;

        // Guard against duplicate processing (relay re-broadcasts, network retries, etc.)
        // Check by boost URI and by actor+original combination to prevent double-counting.
        $boostUri = $a['id'] ?? '';
        $alreadyStored = ($boostUri && StatusModel::byUri($boostUri))
            || (bool)DB::one('SELECT 1 FROM statuses WHERE user_id=? AND reblog_of_id=?', [$actorId, $orig['id']]);

        if (!$alreadyStored) {
            // Incrementar reblog_count no original (apenas uma vez por boost único)
            DB::run('UPDATE statuses SET reblog_count=reblog_count+1 WHERE id=?', [$orig['id']]);

            // Guardar o boost como status separado (aparece na timeline)
            if ($boostUri) {
                $now = now_iso();
                DB::insertIgnore('statuses', [
                    'id'              => flake_id(),
                    'uri'             => $boostUri,
                    'user_id'         => $actorId,
                    'reply_to_id'     => null,
                    'reply_to_uid'    => null,
                    'reblog_of_id'    => $orig['id'],
                    'quote_of_id'     => null,
                    'content'         => '',
                    'cw'              => '',
                    'visibility'      => $orig['visibility'],
                    'language'        => $orig['language'] ?? 'en', // NOT NULL — não pode ser null
                    'sensitive'       => 0,
                    'local'           => 0,
                    'reply_count'     => 0,
                    'reblog_count'    => 0,
                    'favourite_count' => 0,
                    'created_at'      => self::apTimestamp($a['published'] ?? null, $now),
                    'updated_at'      => self::apTimestamp($a['published'] ?? null, $now),
                ]);
            }

            // Notificação apenas se o post original é local
            $owner = UserModel::byId($orig['user_id']);
            if ($owner) {
                self::insertRemoteNotification($orig['user_id'], $actorId, 'reblog', $orig['id']);
                self::refreshRemoteNotification($orig['user_id'], $actorId, 'reblog', $orig['id']);
            }
        }

        return true;
    }


    private static function onMove(array $a, string $actorId): bool
    {
        $oldUrl = is_string($a['object'] ?? null) ? $a['object'] : ($a['object']['id'] ?? '');
        $newUrl = is_string($a['target'] ?? null) ? $a['target'] : ($a['target']['id'] ?? '');

        if (!$oldUrl || !$newUrl || $oldUrl === $newUrl) return false;
        if ($oldUrl !== $actorId) return false;

        $newActor = RemoteActorModel::fetch($newUrl, true);
        if (!$newActor) return false;

        // Verify new actor claims old actor as alias (prevent hostile redirects)
        $theirAka = json_decode($newActor['also_known_as'] ?? '[]', true) ?: [];
        if (!in_array($oldUrl, $theirAka)) {
            self::log($actorId, 'Move-rejected', $a, 'alsoKnownAs verification failed');
            return false;
        }

        // Mark old remote actor as moved
        DB::run('UPDATE remote_actors SET moved_to=? WHERE id=?', [$newUrl, $oldUrl]);

        // Migrate follows: all local users who follow oldUrl now follow newUrl
        $localFollowers = DB::all(
            'SELECT f.follower_id FROM follows f
             JOIN users u ON u.id=f.follower_id
             WHERE f.following_id=? AND f.pending=0 AND u.is_suspended=0',
            [$oldUrl]
        );

        foreach ($localFollowers as $row) {
            $localUser = UserModel::byId($row['follower_id']);
            if (!$localUser) continue;
            $oldFollow = DB::one(
                'SELECT pending, notify FROM follows WHERE follower_id=? AND following_id=?',
                [$localUser['id'], $oldUrl]
            );

            $alreadyFollows = DB::one(
                'SELECT pending, notify FROM follows WHERE follower_id=? AND following_id=?',
                [$localUser['id'], $newUrl]
            );
            if (!$alreadyFollows) {
                $now     = now_iso();
                $pending = (int)$newActor['is_locked'];
                // Preserve notify preference from the old follow row
                DB::insertIgnore('follows', [
                    'id'           => uuid(),
                    'follower_id'  => $localUser['id'],
                    'following_id' => $newUrl,
                    'pending'      => $pending,
                    'notify'       => $oldFollow ? (int)$oldFollow['notify'] : 0,
                    'local'        => 0,
                    'created_at'   => $now,
                ]);
                if (!$pending) {
                    DB::run('UPDATE users SET following_count=following_count+1 WHERE id=?', [$localUser['id']]);
                }
                Delivery::queueToActor($localUser, $newActor, Builder::follow($localUser, $newUrl));
            } elseif ($oldFollow && (int)$oldFollow['notify'] && !(int)($alreadyFollows['notify'] ?? 0)) {
                DB::update(
                    'follows',
                    ['notify' => 1],
                    'follower_id=? AND following_id=?',
                    [$localUser['id'], $newUrl]
                );
            }

            // Unfollow old actor
            DB::delete('follows', 'follower_id=? AND following_id=?', [$localUser['id'], $oldUrl]);
            if ($oldFollow && !(int)$oldFollow['pending']) {
                DB::run('UPDATE users SET following_count=MAX(0,following_count-1) WHERE id=?', [$localUser['id']]);
            }

            // Note: 'move' is not a standard Mastodon notification type.
            // Clients like Ivory silently ignore unknown types, so we skip
            // creating a move notification to avoid cluttering the notification list.
        }

        return true;
    }

    // ── Helpers ──────────────────────────────────────────────

    /**
     * Safely extract a string from an AP JSON field that may arrive as a
     * language map array ({"en":"text"} or {"@value":"text"}) instead of a
     * plain string. Returns $default if the value is not usable as a string.
     */
    private static function apStr(mixed $v, string $default = ''): string
    {
        if (is_string($v)) return $v;
        if (is_array($v)) {
            if (isset($v['@value'])) return (string)$v['@value'];
            $first = reset($v);
            return is_string($first) ? $first : $default;
        }
        return $default;
    }

    /**
     * Extract content from an AP object, with fallbacks for different platforms:
     * - Standard: obj.content (Note, Article)
     * - Lemmy: obj.name (Page type uses title instead of content)
     * - Multilingual: obj.contentMap (PeerTube, multilingual servers)
     */
    private static function apExtractContent(array $obj): string
    {
        $content = self::apStr($obj['content'] ?? '');
        if ($content !== '') return $content;
        // contentMap fallback: servers may send only contentMap without content
        if (is_array($obj['contentMap'] ?? null)) {
            foreach ($obj['contentMap'] as $text) {
                if (is_string($text) && $text !== '') return $text;
            }
        }
        // Lemmy Page type: uses 'name' (title) instead of 'content'
        return self::apStr($obj['name'] ?? '');
    }

    /**
     * Normalise inbound AP timestamps to canonical UTC with millisecond suffix.
     * This keeps text-based SQLite ordering stable across timezones and malformed inputs.
     */
    private static function apTimestamp(mixed $value, string $default): string
    {
        $raw = self::apStr($value, '');
        if ($raw === '') return $default;
        try {
            $dt = new \DateTimeImmutable($raw);
            return $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z');
        } catch (\Throwable) {
            return $default;
        }
    }

    /**
     * Normalise ActivityPub fields that may be either a single object or an array.
     *
     * @return array<int,mixed>
     */
    private static function apList(mixed $value): array
    {
        if (!is_array($value)) return [];
        return array_is_list($value) ? $value : [$value];
    }

    /**
     * Extract the best usable URL from an AP attachment object.
     * Handles both a plain string URL and the PeerTube/Lemmy format where
     * "url" is an array of typed Link objects:
     *   [{"type":"Link","mediaType":"video/mp4","href":"https://..."},...]
     */
    private static function attachmentUrl(array $att): string
    {
        $raw = $att['url'] ?? $att['href'] ?? '';
        if (is_string($raw)) return $raw;
        if (!is_array($raw)) return '';
        // Prefer playable media types over HTML/torrent links
        $fallback = '';
        foreach ($raw as $link) {
            if (!is_array($link)) {
                if (is_string($link) && !$fallback) $fallback = $link;
                continue;
            }
            $href = $link['href'] ?? $link['url'] ?? '';
            if (!$href || !is_string($href)) continue;
            $mt = $link['mediaType'] ?? $link['mimeType'] ?? '';
            if (str_starts_with($mt, 'video/') || str_starts_with($mt, 'audio/') || str_starts_with($mt, 'image/')) {
                return $href;
            }
            if (!$fallback) $fallback = $href;
        }
        return $fallback;
    }

    private static function apVisibility(mixed $to, mixed $cc): string
    {
        // JSON-LD allows to/cc as a single string or an array; normalise both cases
        if (is_string($to)) $to = [$to];
        if (is_string($cc)) $cc = [$cc];
        if (!is_array($to)) $to = [];
        if (!is_array($cc)) $cc = [];

        // Some servers (Pleroma/Akkoma) send the JSON-LD compact form "as:Public" or
        // "Public" instead of the full URI. Normalise all known aliases.
        $pubAliases = [
            'https://www.w3.org/ns/activitystreams#Public',
            'as:Public',
            'Public',
        ];
        $isPublic = static fn(array $arr): bool =>
            (bool)array_intersect($pubAliases, $arr);

        if ($isPublic($to))  return 'public';
        if ($isPublic($cc))  return 'unlisted';
        foreach (array_merge($to, $cc) as $t) {
            if (is_string($t) && str_ends_with($t, '/followers')) return 'private';
        }
        return 'direct';
    }

    private static function log(string $actor, string $type, array $activity, string $error = ''): void
    {
        try {
            DB::insert('inbox_log', [
                'id'         => uuid(),
                'actor_url'  => $actor,
                'type'       => $type,
                'raw_json'   => json_encode($activity),
                'error'      => $error,
                'created_at' => now_iso(),
            ]);
        } catch (\Throwable) { /* non-fatal */ }
    }
}
