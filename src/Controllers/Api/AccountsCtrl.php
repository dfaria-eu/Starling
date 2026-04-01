<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, StatusModel, OAuthModel, MediaModel, RemoteActorModel};
use App\ActivityPub\{Builder, Delivery};

    class AccountsCtrl
    {
    private function primeRemoteStatusesFromOutbox(array $remote, int $limit): void
    {
        $outboxUrl = $remote['outbox_url'] ?? '';
        if ($outboxUrl === '') return;

        $accept = 'application/activity+json';
        $outbox = RemoteActorModel::httpGet($outboxUrl, $accept);
        if (!$outbox) {
            $outbox = RemoteActorModel::httpGet($outboxUrl . (str_contains($outboxUrl, '?') ? '&' : '?') . 'page=true', $accept);
        }
        if (!$outbox) return;

        $items = $outbox['orderedItems'] ?? $outbox['items'] ?? null;
        if (!is_array($items) && isset($outbox['first'])) {
            $firstUrl = is_string($outbox['first']) ? $outbox['first'] : ($outbox['first']['id'] ?? '');
            if ($firstUrl !== '') {
                $page  = RemoteActorModel::httpGet($firstUrl, $accept);
                $items = $page['orderedItems'] ?? $page['items'] ?? [];
            }
        }
        if (!is_array($items)) return;

        $now = now_iso();
        foreach (array_slice($items, 0, $limit) as $item) {
            $obj = null;
            if (is_array($item)) {
                $type = $item['type'] ?? '';
                if ($type === 'Note') {
                    $obj = $item;
                } elseif (in_array($type, ['Create', 'Update'], true) && is_array($item['object'] ?? null)) {
                    $obj = $item['object'];
                }
            }
            if (!is_array($obj) || ($obj['type'] ?? '') !== 'Note') continue;

            $uri = (string)($obj['id'] ?? '');
            if ($uri === '' || StatusModel::byUri($uri)) continue;

            DB::insertIgnore('statuses', [
                'id'              => flake_id(),
                'uri'             => $uri,
                'user_id'         => $remote['id'],
                'reply_to_id'     => null,
                'reply_to_uid'    => null,
                'reblog_of_id'    => null,
                'quote_of_id'     => null,
                'content'         => is_string($obj['content'] ?? null) ? $obj['content'] : '',
                'cw'              => is_string($obj['summary'] ?? null) ? $obj['summary'] : '',
                'visibility'      => 'public',
                'language'        => is_string($obj['language'] ?? null) ? $obj['language'] : 'en',
                'sensitive'       => (int)bool_val($obj['sensitive'] ?? false),
                'local'           => 0,
                'reply_count'     => 0,
                'reblog_count'    => 0,
                'favourite_count' => 0,
                'created_at'      => is_string($obj['published'] ?? null) ? $obj['published'] : $now,
                'updated_at'      => is_string($obj['updated'] ?? null) ? $obj['updated'] : (is_string($obj['published'] ?? null) ? $obj['published'] : $now),
            ]);
        }
    }

    // ── Registration ─────────────────────────────────────────

    public function register(array $p): void
    {
        if (!AP_OPEN_REG) err_out('Registration closed', 403);

        $d  = req_body();
        $un = trim(strtolower($d['username'] ?? ''));
        $em = trim(strtolower($d['email'] ?? ''));
        $pw = $d['password'] ?? '';

        if (!$un || !$em || !$pw)                   err_out('username, email and password required', 422);
        if (!preg_match('/^\w{1,30}$/', $un))        err_out('Invalid username', 422);
        if (!filter_var($em, FILTER_VALIDATE_EMAIL)) err_out('Invalid email', 422);
        if (strlen($pw) < 8)                         err_out('Password too short (min 8)', 422);
        // Check if username exists (including suspended accounts)
        $existingUser = UserModel::byUsernameAny($un);
        if ($existingUser) {
            if ($existingUser['is_suspended']) err_out('Account suspended', 403);
            err_out('Username taken', 422);
        }
        $existingEmail = UserModel::byEmailAny($em);
        if ($existingEmail) {
            if ($existingEmail['is_suspended']) err_out('Account suspended', 403);
            err_out('Email registered', 422);
        }

        $clientId = (string)($d['client_id'] ?? '');
        $app   = $clientId !== ''
            ? OAuthModel::appByClientId($clientId)
            : ['id' => '', 'scopes' => 'read write follow push'];
        if ($clientId !== '' && !$app) err_out('Invalid client', 422);
        $user  = UserModel::create(['username' => $un, 'email' => $em, 'password' => $pw]);
        $token = OAuthModel::createToken($app['id'], $user['id'], $app['scopes']);

        json_out(['access_token' => $token, 'token_type' => 'Bearer', 'scope' => $app['scopes'], 'created_at' => time(), 'expires_in' => 315360000]);
    }

    // ── Credentials ──────────────────────────────────────────

    public function verifyCredentials(array $p): void
    {
        $user = require_auth('read');
        json_out(UserModel::toMasto($user, $user['id'], true));
    }

    public function updateCredentials(array $p): void
    {
        $user = require_auth('write');
        $d    = req_body();
        $upd  = [];
        $src  = is_array($d['source'] ?? null) ? $d['source'] : [];

        if (isset($d['display_name'])) $upd['display_name'] = safe_str($d['display_name'], 100);
        if (isset($d['note']))         $upd['bio']          = safe_str($d['note'], 500);
        elseif (isset($src['note']))   $upd['bio']          = safe_str((string)$src['note'], 500);
        if (isset($d['locked']))       $upd['is_locked']    = (int)bool_val($d['locked']);
        if (isset($d['bot']))          $upd['is_bot']       = (int)bool_val($d['bot']);
        if (isset($d['discoverable'])) $upd['discoverable'] = (int)bool_val($d['discoverable']);
        if (isset($d['indexable']))    $upd['indexable']    = (int)bool_val($d['indexable']);

        $fieldAttrs = $d['fields_attributes'] ?? ($src['fields_attributes'] ?? null);
        if ($fieldAttrs === null && isset($src['fields']) && is_array($src['fields'])) {
            $fieldAttrs = $src['fields'];
        }
        if ($fieldAttrs !== null) {
            $actorUrl    = actor_url($user['username']);
            $existFields = json_decode($user['fields'] ?? '[]', true) ?: [];
            // Index existing fields by value for preserving verified_at when unchanged
            $existByValue = [];
            foreach ($existFields as $ef) {
                $existByValue[trim($ef['value'] ?? '')] = $ef['verified_at'] ?? null;
            }
            $fields = [];
            foreach (array_slice((array)$fieldAttrs, 0, 4) as $f) {
                $name  = trim((string)($f['name']  ?? ''));
                $value = UserModel::normalizeProfileFieldValue((string)($f['value'] ?? ''));
                if ($name === '') continue;
                // Preserve verified_at only if already verified; re-check if null
                $existingVerified = $existByValue[$value] ?? null;
                if ($existingVerified !== null) {
                    $verifiedAt = $existingVerified;
                } else {
                    $verifiedAt = \App\Models\UserModel::verifyRelMe($value, $actorUrl);
                }
                $fields[] = ['name' => $name, 'value' => $value, 'verified_at' => $verifiedAt];
            }
            $upd['fields'] = json_encode($fields);
        }

        // Preferences (posting defaults) and settings that may arrive inside source[...]
        if ($src) {
            $existingPrefs = json_decode($user['preferences'] ?? '{}', true) ?: [];
            if (isset($src['privacy']))       $existingPrefs['posting:default:visibility'] = $src['privacy'];
            if (isset($src['sensitive']))     $existingPrefs['posting:default:sensitive']  = bool_val($src['sensitive']);
            if (isset($src['language']))      $existingPrefs['posting:default:language']   = $src['language'];
            if (array_key_exists('expire_after', $src)) {
                $expireAfter = (int)($src['expire_after'] ?? 0);
                $existingPrefs['posting:default:expire_after'] = $expireAfter > 0 ? $expireAfter : null;
            }
            if (isset($src['reading:expand:media']))    $existingPrefs['reading:expand:media']    = (string)$src['reading:expand:media'];
            if (isset($src['reading:expand:spoilers'])) $existingPrefs['reading:expand:spoilers'] = bool_val($src['reading:expand:spoilers']);
            if (isset($src['reading:autoplay:gifs']))   $existingPrefs['reading:autoplay:gifs']   = bool_val($src['reading:autoplay:gifs']);
            $upd['preferences'] = json_encode($existingPrefs);
            // Some clients send discoverable/indexable inside source instead of top-level
            if (isset($src['indexable']))    $upd['indexable']    = (int)bool_val($src['indexable']);
            if (isset($src['discoverable'])) $upd['discoverable'] = (int)bool_val($src['discoverable']);
        }

        if (!empty($_FILES['avatar']['tmp_name'])) {
            $m = MediaModel::upload($_FILES['avatar'], $user['id']);
            if ($m) $upd['avatar'] = $m['url'];
        }
        if (!empty($_FILES['header']['tmp_name'])) {
            $m = MediaModel::upload($_FILES['header'], $user['id']);
            if ($m) $upd['header'] = $m['url'];
        }

        // Password change: requires current_password + new password
        if (isset($d['current_password']) && isset($d['password'])) {
            if (!password_verify($d['current_password'], $user['password'] ?? ''))
                err_out('Current password is incorrect.', 422);
            if (strlen($d['password']) < 8)
                err_out('New password must be at least 8 characters long.', 422);
            $upd['password'] = password_hash($d['password'], PASSWORD_BCRYPT);
        }

        if ($upd) {
            UserModel::update($user['id'], $upd);
            // Federate actor update to followers (skip if only password changed)
            if (array_diff_key($upd, ['password' => 1])) {
                $updated = UserModel::byId($user['id']);
                \App\ActivityPub\Delivery::queueToFollowers($updated, \App\ActivityPub\Builder::updateActor($updated));
            }
        }
        json_out(UserModel::toMasto(UserModel::byId($user['id']), $user['id'], true));
    }

    // ── Account lookup ───────────────────────────────────────

    /**
     * GET /api/v1/accounts/lookup?acct=user@domain
     * Used by Ivory and other clients to resolve a handle to an account object.
     */
    public function lookup(array $p): void
    {
        $acct = trim($_GET['acct'] ?? '');
        if (!$acct) err_out('Missing acct parameter', 422);

        if (str_contains($acct, '@')) {
            [$username, $domain] = explode('@', ltrim($acct, '@'), 2);
            if (is_local($domain)) {
                $u = UserModel::byUsername($username);
                if ($u) json_out(UserModel::toMasto($u));
                err_out('Not found', 404);
            }
            // Remote: try cached first, then fetch via WebFinger
            $ra = DB::one('SELECT * FROM remote_actors WHERE username=? AND domain=?', [strtolower($username), strtolower($domain)]);
            if (!$ra) {
                $ra = \App\Models\RemoteActorModel::fetchByAcct($username, $domain);
            } elseif ((int)$ra['follower_count'] === 0 && (int)$ra['following_count'] === 0
                   && time() - (int)strtotime($ra['fetched_at']) > 300) {
                $actorId = $ra['id'];
                defer_after_response(static function () use ($actorId): void {
                    if (throttle_allow('remote_actor_refresh:' . $actorId, 1800)) {
                        \App\Models\RemoteActorModel::fetch($actorId, true);
                    }
                });
            }
            if ($ra) json_out(UserModel::remoteToMasto($ra));
            err_out('Not found', 404);
        }

        // No domain → look up local user
        $u = UserModel::byUsername(ltrim($acct, '@'));
        if ($u) json_out(UserModel::toMasto($u));
        err_out('Not found', 404);
    }

    public function show(array $p): void
    {
        [$local, $remote] = $this->resolve($p['id']);
        if ($local)  { json_out(UserModel::toMasto($local)); return; }
        if ($remote) {
            // Never block profile rendering on remote refreshes. Refresh after the response
            // so iOS/web profile screens don't sit forever with the follow button spinning.
            $age = time() - (int)strtotime($remote['fetched_at']);
            if ($age > 300) {
                $actorId = $remote['id'];
                defer_after_response(static function () use ($actorId): void {
                    if (throttle_allow('remote_actor_refresh:' . $actorId, 1800)) {
                        RemoteActorModel::fetch($actorId, true);
                    }
                });
            }
            json_out(UserModel::remoteToMasto($remote));
            return;
        }
        err_out('Not found', 404);
    }

    public function statuses(array $p): void
    {
        $viewer = authed_user();
        [$local, $remote] = $this->resolve($p['id']);
        if (!$local && !$remote) err_out('Not found', 404);

        $limit   = min((int)($_GET['limit'] ?? 20), 40);
        $maxId   = $_GET['max_id']   ?? null;
        $sinceId = $_GET['since_id'] ?? null;
        $minId   = $_GET['min_id']   ?? null;
        $exRep   = filter_var($_GET['exclude_replies'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $exReb   = filter_var($_GET['exclude_reblogs'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $onlyM   = filter_var($_GET['only_media']     ?? false, FILTER_VALIDATE_BOOLEAN);
        $pinned  = filter_var($_GET['pinned']         ?? false, FILTER_VALIDATE_BOOLEAN);
        $tagged  = $_GET['tagged'] ?? null;

        // ID interno (UUID para locais, URL AP para remotos)
        $userId = $local ? $local['id'] : $remote['id'];

        if ($pinned) {
            // Remote accounts: we don't cache their pin list — return empty rather than
            // confusing clients with random recent posts having pinned:false.
            if (!$local) { json_out([]); return; }

            $pins = DB::all(
                'SELECT s.* FROM statuses s JOIN status_pins sp ON sp.status_id=s.id
                 WHERE sp.user_id=? ORDER BY sp.created_at DESC LIMIT ?',
                [$userId, $limit]
            );
            json_out(array_values(array_filter(
                array_map(fn($s) => StatusModel::toMasto($s, $viewer['id'] ?? null), $pins)
            )));
            return;
        }

        // Verificar quantos posts temos localmente para esta conta
        $localCount = (int)(DB::one('SELECT COUNT(*) AS n FROM statuses WHERE user_id=?', [$userId])['n'] ?? 0);

        // Para contas remotas sem posts locais, prime o cache depois da resposta.
        // Bloquear aqui faz o perfil remoto parecer "preso" no iOS/web.
        if ($remote && $localCount === 0 && !$maxId && !$sinceId) {
            $remoteCopy = $remote;
            defer_after_response(function () use ($remoteCopy, $limit): void {
                if (throttle_allow('remote_outbox_prime:' . ($remoteCopy['id'] ?? ''), 1800)) {
                    $this->primeRemoteStatusesFromOutbox($remoteCopy, $limit);
                }
            });
        }

        // Visibility filter: direct messages are never public; private/followers-only
        // posts are only visible to the author or their followers.
        $viewerId = $viewer['id'] ?? null;
        $isOwner  = $viewerId && ($viewerId === $userId);
        if ($isOwner) {
            // Owner sees all their own posts
            $visFilter = '';
        } elseif ($viewerId && $local) {
            // Authenticated viewer: can see public, unlisted, and private if following
            $isFollowing = (bool)DB::one(
                'SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=0',
                [$viewerId, $userId]
            );
            $visFilter = $isFollowing
                ? " AND s.visibility IN ('public','unlisted','private')"
                : " AND s.visibility IN ('public','unlisted')";
        } else {
            // Unauthenticated or remote account: only public + unlisted
            $visFilter = " AND s.visibility IN ('public','unlisted')";
        }

        $sql = 'SELECT s.* FROM statuses s WHERE s.user_id=?' . $visFilter;
        $par = [$userId];

        // Paginação por (created_at, id) — cursor composto evita duplicados
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$maxId]);
            if ($ref) { $sql .= ' AND (s.created_at < ? OR (s.created_at = ? AND s.id < ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($sinceId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$sinceId]);
            if ($ref) { $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($minId) {
            $ref = DB::one('SELECT created_at, id FROM statuses WHERE id=?', [$minId]);
            if ($ref) { $sql .= ' AND (s.created_at > ? OR (s.created_at = ? AND s.id > ?))'; $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id']; }
        }
        if ($exRep) $sql .= ' AND s.reply_to_id IS NULL';
        if ($exReb) $sql .= ' AND s.reblog_of_id IS NULL';
        if ($onlyM) $sql .= ' AND s.id IN (SELECT status_id FROM status_media)';
        if ($tagged) {
            $htag  = mb_strtolower(ltrim((string)$tagged, '#'), 'UTF-8');
            $sql  .= ' AND s.id IN (SELECT sh.status_id FROM status_hashtags sh JOIN hashtags h ON h.id=sh.hashtag_id WHERE h.name=?)';
            $par[] = $htag;
        }
        if ($minId) {
            $sql .= ' ORDER BY s.created_at ASC, s.id ASC LIMIT ?';
        } else {
            $sql .= ' ORDER BY s.created_at DESC, s.id DESC LIMIT ?';
        }
        $par[] = $limit;

        $rows = DB::all($sql, $par);
        $out  = array_values(array_filter(
            array_map(fn($s) => StatusModel::toMasto($s, $viewer['id'] ?? null), $rows)
        ));
        if ($minId && $out) $out = array_reverse($out);
        if ($out) {
            $base       = ap_url('api/v1/accounts/' . $p['id'] . '/statuses');
            $common     = array_filter([
                'limit'            => $limit,
                'exclude_replies'  => $exRep ? 'true' : null,
                'exclude_reblogs'  => $exReb ? 'true' : null,
                'only_media'       => $onlyM ? 'true' : null,
                'pinned'           => $pinned ? 'true' : null,
                'tagged'           => $tagged ?: null,
            ]);
            $nextParams = http_build_query(array_merge($common, ['max_id' => end($out)['id']]));
            $prevParams = http_build_query(array_merge($common, ['min_id' => reset($out)['id']]));
            header(sprintf('Link: <%s?%s>; rel="next", <%s?%s>; rel="prev"', $base, $nextParams, $base, $prevParams));
        }
        json_out($out);
    }

    public function followers(array $p): void
    {
        [$local, $remote] = $this->resolve($p['id']);
        if (!$local && !$remote) err_out('Not found', 404);

        // Remote account: fetch followers collection from their server
        if (!$local && $remote) {
            json_out($this->remoteCollection($remote['followers_url'] ?? ''));
            return;
        }

        $limit = min((int)($_GET['limit'] ?? 40), 80);
        $maxId = $_GET['max_id'] ?? null;

        $sql = 'SELECT follower_id, id FROM follows WHERE following_id=? AND pending=0';
        $par = [$local['id']];
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM follows WHERE id=?', [$maxId]);
            if ($ref) {
                $sql .= ' AND (created_at < ? OR (created_at = ? AND id < ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        $sql .= ' ORDER BY created_at DESC, id DESC LIMIT ?'; $par[] = $limit;

        $rows = DB::all($sql, $par);
        $out  = [];
        foreach ($rows as $r) {
            $u = UserModel::byId($r['follower_id']);
            if ($u) { $out[] = UserModel::toMasto($u); continue; }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$r['follower_id']]);
            if ($ra) $out[] = UserModel::remoteToMasto($ra);
        }
        if ($out && count($rows) === $limit) {
            $base = ap_url("api/v1/accounts/{$p['id']}/followers");
            header(sprintf('Link: <%s?%s>; rel="next"', $base, http_build_query(['limit' => $limit, 'max_id' => end($rows)['id']])));
        }
        json_out($out);
    }

    public function following(array $p): void
    {
        [$local, $remote] = $this->resolve($p['id']);
        if (!$local && !$remote) err_out('Not found', 404);

        // Remote account: fetch following collection from their server
        if (!$local && $remote) {
            json_out($this->remoteCollection($remote['following_url'] ?? ''));
            return;
        }

        $limit = min((int)($_GET['limit'] ?? 40), 80);
        $maxId = $_GET['max_id'] ?? null;

        $sql = 'SELECT following_id, id FROM follows WHERE follower_id=? AND pending=0';
        $par = [$local['id']];
        if ($maxId) {
            $ref = DB::one('SELECT created_at, id FROM follows WHERE id=?', [$maxId]);
            if ($ref) {
                $sql .= ' AND (created_at < ? OR (created_at = ? AND id < ?))';
                $par[] = $ref['created_at']; $par[] = $ref['created_at']; $par[] = $ref['id'];
            }
        }
        $sql .= ' ORDER BY created_at DESC, id DESC LIMIT ?'; $par[] = $limit;

        $rows = DB::all($sql, $par);
        $out  = [];
        foreach ($rows as $r) {
            $u = UserModel::byId($r['following_id']);
            if ($u) { $out[] = UserModel::toMasto($u); continue; }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$r['following_id']]);
            if ($ra) $out[] = UserModel::remoteToMasto($ra);
        }
        if ($out && count($rows) === $limit) {
            $base = ap_url("api/v1/accounts/{$p['id']}/following");
            header(sprintf('Link: <%s?%s>; rel="next"', $base, http_build_query(['limit' => $limit, 'max_id' => end($rows)['id']])));
        }
        json_out($out);
    }

    /**
     * Fetch an ActivityPub OrderedCollection (followers or following) from a remote server,
     * resolve each actor URI to a Mastodon account object, and return the list.
     * Returns empty array if the collection is hidden or unreachable.
     */
    private function remoteCollection(string $collectionUrl): array
    {
        if (!$collectionUrl) return [];

        $accept = 'application/activity+json';

        // Fetch collection root to get totalItems and first page URL
        $coll = \App\Models\RemoteActorModel::httpGet($collectionUrl, $accept);
        if (!$coll || !isset($coll['type'])) return [];

        // Some servers return items directly in root; others use orderedItems or first page
        $items = $coll['orderedItems'] ?? $coll['items'] ?? null;

        if (!$items && isset($coll['first'])) {
            $firstUrl = is_string($coll['first']) ? $coll['first'] : ($coll['first']['id'] ?? '');
            if ($firstUrl) {
                $page  = \App\Models\RemoteActorModel::httpGet($firstUrl, $accept);
                $items = $page['orderedItems'] ?? $page['items'] ?? [];
            }
        }

        if (!is_array($items)) return [];

        $out = [];
        foreach (array_slice($items, 0, 80) as $item) {
            $actorUrl = is_string($item) ? $item : ($item['id'] ?? '');
            if (!$actorUrl) continue;

            // Check local cache first, fetch if missing
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$actorUrl])
               ?? \App\Models\RemoteActorModel::fetch($actorUrl);
            if ($ra) {
                $out[] = UserModel::remoteToMasto($ra);
            }
        }
        return $out;
    }

    // ── Follow / unfollow ─────────────────────────────────────

    public function follow(array $p): void
    {
        $viewer = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);

        // Determine canonical target ID (local UUID or remote AP URL)
        if ($local) {
            $targetId = $local['id'];
            if ($viewer['id'] === $targetId) err_out('Cannot follow yourself', 422);
        } elseif ($remote) {
            $targetId = $remote['id']; // AP URL
        } else {
            err_out('Not found', 404);
        }

        $d      = req_body();
        $notify = (int)bool_val($d['notify'] ?? false);

        $exists = DB::one('SELECT pending, notify FROM follows WHERE follower_id=? AND following_id=?', [$viewer['id'], $targetId]);
        if (!$exists) {
            $isLocked = $local ? (int)$local['is_locked'] : (int)$remote['is_locked'];
            $pending  = $isLocked ? 1 : 0;

            DB::insertIgnore('follows', [
                'id'          => uuid(),
                'follower_id' => $viewer['id'],
                'following_id'=> $targetId,
                'pending'     => $pending,
                'notify'      => $notify,
                'local'       => $local ? 1 : 0,
                'created_at'  => now_iso(),
            ]);

            if (!$pending) {
                // Actualizar following_count do utilizador local sempre (local ou remoto)
                DB::run('UPDATE users SET following_count=following_count+1 WHERE id=?', [$viewer['id']]);
                if ($local) {
                    // follower_count e notificação só para contas locais
                    DB::run('UPDATE users SET follower_count=follower_count+1 WHERE id=?', [$targetId]);
                    DB::insertIgnore('notifications', [
                        'id' => flake_id(), 'user_id' => $targetId, 'from_acct_id' => $viewer['id'],
                        'type' => 'follow', 'status_id' => null, 'read_at' => null, 'created_at' => now_iso(),
                    ]);
                }
            } elseif ($local) {
                // Conta local bloqueada: notificar pedido de seguimento
                DB::insertIgnore('notifications', [
                    'id' => flake_id(), 'user_id' => $targetId, 'from_acct_id' => $viewer['id'],
                    'type' => 'follow_request', 'status_id' => null, 'read_at' => null, 'created_at' => now_iso(),
                ]);
            }

            // Federate Follow to remote actor — queued
            if ($remote) {
                $followActivity = Builder::follow($viewer, $remote['id']);
                Delivery::queueToActor($viewer, $remote, $followActivity);
            }
        } else {
            // Follow already exists — update notify flag if changed
            if ((int)$exists['notify'] !== $notify) {
                DB::update('follows', ['notify' => $notify], 'follower_id=? AND following_id=?', [$viewer['id'], $targetId]);
            }
        }

        // Pass both the client-facing masto_id and the internal AP URL/UUID
        $clientId = $p['id'];
        json_out($this->rel($viewer['id'], $clientId, $targetId));
    }

    public function unfollow(array $p): void
    {
        $viewer = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);

        $targetId = $local ? $local['id'] : ($remote ? $remote['id'] : null);
        if (!$targetId) err_out('Not found', 404);

        $row = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$viewer['id'], $targetId]);
        if ($row) {
            DB::delete('follows', 'follower_id=? AND following_id=?', [$viewer['id'], $targetId]);
            if (!$row['pending']) {
                // Decrementar following_count sempre (independente de local/remoto)
                DB::run('UPDATE users SET following_count=MAX(0,following_count-1) WHERE id=?', [$viewer['id']]);
                if ($local) {
                    DB::run('UPDATE users SET follower_count=MAX(0,follower_count-1) WHERE id=?', [$targetId]);
                }
            }
            // Federate Undo Follow to remote — queued
            if ($remote) {
                $activity = Builder::undoFollow($viewer, $remote['id']);
                Delivery::queueToActor($viewer, $remote, $activity);
            }
        }
        $clientId = $p['id'];
        json_out($this->rel($viewer['id'], $clientId, $targetId));
    }

    /**
     * GET /api/v1/accounts/familiar_followers
     * Returns followers of the given accounts that the viewer also follows.
     */
    public function familiarFollowers(array $p): void
    {
        $viewer = authed_user();
        $ids    = (array)($_GET['id[]'] ?? $_GET['id'] ?? []);
        $out    = [];
        foreach ($ids as $id) {
            if (!$viewer) { $out[] = ['id' => $id, 'accounts' => []]; continue; }
            // Resolve Mastodon client ID to internal ID (UUID for local, AP URL for remote)
            [$loc, $rem] = $this->resolve((string)$id);
            $internalId = $loc ? $loc['id'] : ($rem ? $rem['id'] : (string)$id);
            // Who follows $internalId AND is followed by viewer?
            $rows = DB::all(
                'SELECT f1.follower_id FROM follows f1
                 JOIN follows f2 ON f2.following_id=f1.follower_id AND f2.follower_id=?
                 WHERE f1.following_id=? AND f1.pending=0
                 LIMIT 5',
                [$viewer['id'], $internalId]
            );
            $accounts = [];
            foreach ($rows as $r) {
                $followerId = $r['follower_id'];
                $u = UserModel::byId($followerId);
                if ($u) {
                    $accounts[] = UserModel::toMasto($u, $viewer['id']);
                    continue;
                }
                $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$followerId]);
                if ($ra) {
                    $accounts[] = UserModel::remoteToMasto($ra);
                }
            }
            $out[] = ['id' => $id, 'accounts' => $accounts];
        }
        json_out($out);
    }

    public function block(array $p): void
    {
        $viewer = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);
        $targetId = $local ? $local['id'] : ($remote ? $remote['id'] : $p['id']);
        DB::insertIgnore('blocks', ['id' => uuid(), 'user_id' => $viewer['id'], 'target_id' => $targetId, 'created_at' => now_iso()]);

        // Remove any follow in either direction (Mastodon behaviour)
        $wasFollowing = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$viewer['id'], $targetId]);
        if ($wasFollowing) {
            DB::delete('follows', 'follower_id=? AND following_id=?', [$viewer['id'], $targetId]);
            if (!$wasFollowing['pending']) {
                DB::run('UPDATE users SET following_count=MAX(0,following_count-1) WHERE id=?', [$viewer['id']]);
                if ($local) DB::run('UPDATE users SET follower_count=MAX(0,follower_count-1) WHERE id=?', [$targetId]);
                if ($remote) {
                    $activity = Builder::undoFollow($viewer, $remote['id']);
                    Delivery::queueToActor($viewer, $remote, $activity);
                }
            }
        }
        // Also remove the target's follow of viewer (blocked users can't follow you)
        $wasFollowedBy = DB::one('SELECT pending FROM follows WHERE follower_id=? AND following_id=?', [$targetId, $viewer['id']]);
        if ($wasFollowedBy) {
            DB::delete('follows', 'follower_id=? AND following_id=?', [$targetId, $viewer['id']]);
            if (!$wasFollowedBy['pending']) {
                DB::run('UPDATE users SET follower_count=MAX(0,follower_count-1) WHERE id=?', [$viewer['id']]);
                if ($remote) DB::run('UPDATE remote_actors SET following_count=MAX(0,following_count-1) WHERE id=?', [$targetId]);
                if ($local)  DB::run('UPDATE users SET following_count=MAX(0,following_count-1) WHERE id=?', [$targetId]);
            }
        }

        if ($remote) {
            Delivery::queueToActor($viewer, $remote, Builder::block($viewer, $remote['id']));
        }

        json_out($this->rel($viewer['id'], $p['id'], $targetId));
    }

    public function unblock(array $p): void
    {
        $viewer = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);
        $targetId = $local ? $local['id'] : ($remote ? $remote['id'] : $p['id']);
        DB::delete('blocks', 'user_id=? AND target_id=?', [$viewer['id'], $targetId]);
        if ($remote) {
            Delivery::queueToActor($viewer, $remote, Builder::undoBlock($viewer, $remote['id']));
        }
        json_out($this->rel($viewer['id'], $p['id'], $targetId));
    }

    public function mute(array $p): void
    {
        $viewer = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);
        $targetId = $local ? $local['id'] : ($remote ? $remote['id'] : $p['id']);
        DB::insertIgnore('mutes', ['id' => uuid(), 'user_id' => $viewer['id'], 'target_id' => $targetId, 'created_at' => now_iso()]);
        json_out($this->rel($viewer['id'], $p['id'], $targetId));
    }

    public function unmute(array $p): void
    {
        $viewer = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);
        $targetId = $local ? $local['id'] : ($remote ? $remote['id'] : $p['id']);
        DB::delete('mutes', 'user_id=? AND target_id=?', [$viewer['id'], $targetId]);
        json_out($this->rel($viewer['id'], $p['id'], $targetId));
    }

    public function relationships(array $p): void
    {
        $viewer = require_auth('read');
        $ids    = (array)($_GET['id'] ?? []);
        json_out(array_map(fn($id) => $this->rel($viewer['id'], $id), $ids));
    }

    public function search(array $p): void
    {
        $q = trim($_GET['q'] ?? '');
        if (!$q) { json_out([]); return; }
        $limit = max(1, min((int)($_GET['limit'] ?? 5), 40));

        // Escape LIKE wildcards so literal '%' and '_' in the query don't match unintended rows
        $qLike = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';

        // Local users
        $local = DB::all(
            "SELECT * FROM users WHERE (username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\') AND is_suspended=0 LIMIT ?",
            [$qLike, $qLike, $limit]
        );
        $out = array_map(fn($u) => UserModel::toMasto($u), $local);

        // Remote actors in cache
        if (str_contains($q, '@')) {
            [$un, $dom] = array_pad(explode('@', ltrim($q, '@'), 2), 2, '');
            if ($un && $dom) {
                if (is_local($dom)) {
                    $u = UserModel::byUsername($un);
                    if ($u) $out[] = UserModel::toMasto($u);
                } else {
                    $ra = RemoteActorModel::fetchByAcct($un, $dom);
                    if ($ra) $out[] = UserModel::remoteToMasto($ra);
                }
            }
        } else {
            $remote = DB::all(
                "SELECT * FROM remote_actors
                 WHERE domain != ?
                   AND (username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\')
                 LIMIT ?",
                [AP_DOMAIN, $qLike, $qLike, $limit]
            );
            foreach ($remote as $ra) $out[] = UserModel::remoteToMasto($ra);
        }

        $dedup = [];
        foreach ($out as $row) {
            $key = $row['uri'] ?? ($row['acct'] ?? $row['id']);
            if (!isset($dedup[$key])) $dedup[$key] = $row;
        }
        json_out(array_slice(array_values($dedup), 0, $limit));
    }

    // ── Helpers ──────────────────────────────────────────────

    /**
     * Resolve an account ID (local UUID or md5 of remote AP URL) to
     * [?localUser, ?remoteActor]. Exactly one will be non-null.
     */
    private function resolve(string $id): array
    {
        // Try local user by UUID
        $local = UserModel::byId($id);
        if ($local) return [$local, null];

        // Try remote actor by masto_id (md5 of AP URL, stored at upsert time)
        $remote = DB::one('SELECT * FROM remote_actors WHERE masto_id=?', [$id]);

        return [null, $remote ?: null];
    }

    /**
     * Build a relationship object.
     * $clientId = the masto_id the client knows (UUID for local, md5 for remote)
     * $internalId = the internal target ID used in DB (UUID for local, AP URL for remote)
     */
    private function rel(string $vid, string $clientId, ?string $internalId = null): array
    {
        // If internalId not provided, resolve it from clientId
        if ($internalId === null) {
            [$loc, $rem] = $this->resolve($clientId);
            $internalId = $loc ? $loc['id'] : ($rem ? $rem['id'] : $clientId);
        }

        // domain_blocking: verificar se o viewer bloqueou o domínio do actor remoto
        $domainBlocking = false;
        if (str_starts_with((string)$internalId, 'http')) {
            $ra = DB::one('SELECT domain FROM remote_actors WHERE id=?', [$internalId]);
            if ($ra) {
                $domainBlocking = (bool)DB::one('SELECT 1 FROM user_domain_blocks WHERE user_id=? AND domain=?', [$vid, $ra['domain']]);
            }
        }

        $activeFollow = DB::one('SELECT notify FROM follows WHERE follower_id=? AND following_id=? AND pending=0', [$vid, $internalId]);

        return [
            'id'                   => (string)$clientId,   // always the masto_id the client knows
            'following'            => $activeFollow !== null,
            'showing_reblogs'      => true,
            'notifying'            => $activeFollow ? (bool)$activeFollow['notify'] : false,
            'languages'            => [],
            'followed_by'          => (bool)DB::one('SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=0', [$internalId, $vid]),
            'blocking'             => (bool)DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$vid, $internalId]),
            'blocked_by'           => (bool)DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$internalId, $vid]),
            'muting'               => (bool)DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$vid, $internalId]),
            'muting_notifications' => false,
            'requested'            => (bool)DB::one('SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=1', [$vid, $internalId]),
            'requested_by'         => (bool)DB::one('SELECT 1 FROM follows WHERE follower_id=? AND following_id=? AND pending=1', [$internalId, $vid]),
            'domain_blocking'      => $domainBlocking,
            'endorsed'             => (bool)DB::one('SELECT 1 FROM account_endorsements WHERE user_id=? AND target_id=?', [$vid, $internalId]),
            'note'                 => (string)(DB::one('SELECT comment FROM account_notes WHERE user_id=? AND target_id=?', [$vid, $internalId])['comment'] ?? ''),
            'muting_expires_at'    => null,
        ];
    }

    // ── Pinning / notes on accounts (Mastodon compatibility) ──

    /**
     * GET /api/v1/accounts/:id/lists
     * Returns all lists of the authenticated user that contain the given account.
     * Used by Ivory and other clients for the "Add to list / Remove from list" UI.
     */
    public function accountLists(array $p): void
    {
        $user = require_auth('read');
        [$local, $remote] = $this->resolve($p['id']);
        $targetId = $local ? $local['id'] : ($remote ? $remote['id'] : null);
        if (!$targetId) err_out('Not found', 404);

        $rows = DB::all(
            'SELECT l.* FROM lists l
             JOIN list_accounts la ON la.list_id=l.id
             WHERE l.user_id=? AND la.account_id=?
             ORDER BY l.created_at ASC',
            [$user['id'], $targetId]
        );
        json_out(array_map(
            fn($l) => ['id' => $l['id'], 'title' => $l['title'], 'replies_policy' => 'list', 'exclusive' => false],
            $rows
        ));
    }

    public function pinAccount(array $p): void
    {
        $user = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);
        if (!$local && !$remote) err_out('Not found', 404);
        $targetId = $local ? $local['id'] : $remote['id'];
        if ($targetId === $user['id']) err_out('Cannot pin yourself', 422);

        $count = DB::count('account_endorsements', 'user_id=?', [$user['id']]);
        $already = (bool)DB::one('SELECT 1 FROM account_endorsements WHERE user_id=? AND target_id=?', [$user['id'], $targetId]);
        if (!$already && $count >= 4) err_out('Maximum number of endorsed accounts reached', 422);

        DB::insertIgnore('account_endorsements', [
            'id'         => uuid(),
            'user_id'    => $user['id'],
            'target_id'  => $targetId,
            'created_at' => now_iso(),
        ]);
        json_out($this->rel($user['id'], $p['id'], $targetId));
    }

    public function unpinAccount(array $p): void
    {
        $user = require_auth(['follow', 'write']);
        [$local, $remote] = $this->resolve($p['id']);
        if (!$local && !$remote) err_out('Not found', 404);
        $targetId = $local ? $local['id'] : $remote['id'];
        DB::delete('account_endorsements', 'user_id=? AND target_id=?', [$user['id'], $targetId]);
        json_out($this->rel($user['id'], $p['id'], $targetId));
    }

    public function noteAccount(array $p): void
    {
        $user = require_auth(['follow', 'write']);
        $d = req_body();
        [$local, $remote] = $this->resolve($p['id']);
        if (!$local && !$remote) err_out('Not found', 404);
        $targetId = $local ? $local['id'] : $remote['id'];
        $comment = safe_str((string)($d['comment'] ?? $d['note'] ?? ''), 2000);
        $existing = DB::one('SELECT id FROM account_notes WHERE user_id=? AND target_id=?', [$user['id'], $targetId]);
        if ($existing) {
            DB::update('account_notes', ['comment' => $comment, 'updated_at' => now_iso()], 'user_id=? AND target_id=?', [$user['id'], $targetId]);
        } else {
            DB::insert('account_notes', [
                'id'         => uuid(),
                'user_id'    => $user['id'],
                'target_id'  => $targetId,
                'comment'    => $comment,
                'created_at' => now_iso(),
                'updated_at' => now_iso(),
            ]);
        }
        json_out($this->rel($user['id'], $p['id'], $targetId));
    }
}
