<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, StatusModel, AnnouncementsModel, AdminModel, OAuthModel};

// ── Preferences ──────────────────────────────────────────────

class PreferencesCtrl
{
    private const DEFAULTS = [
        'posting:default:visibility'  => 'public',
        'posting:default:sensitive'   => false,
        'posting:default:language'    => null,
        'posting:default:expire_after'=> null,
        'reading:expand:media'        => 'default',
        'reading:expand:spoilers'     => false,
        'reading:autoplay:gifs'       => true,
    ];

    public function show(array $p): void
    {
        $user  = require_auth('read');
        $saved = json_decode($user['preferences'] ?? '{}', true) ?: [];
        json_out(array_merge(self::DEFAULTS, $saved));
    }
}

class SessionsCtrl
{
    public function index(array $p): void
    {
        $user = require_auth('read');
        $currentToken = (string)((auth_context()['token']['token'] ?? '') ?: '');
        $rows = DB::all(
            'SELECT t.token, t.scopes, t.created_at, t.last_used, a.name AS app_name, a.website AS app_website
               FROM oauth_tokens t
          LEFT JOIN oauth_apps a ON a.id=t.app_id
              WHERE t.user_id=?
           ORDER BY CASE WHEN t.token=? THEN 0 ELSE 1 END, COALESCE(NULLIF(t.last_used, \'\'), t.created_at) DESC',
            [$user['id'], $currentToken]
        );

        json_out(array_map(static function (array $row) use ($currentToken): array {
            $token = (string)$row['token'];
            return [
                'id' => $token,
                'current' => hash_equals($currentToken, $token),
                'created_at' => $row['created_at'],
                'last_used_at' => $row['last_used'] !== '' ? $row['last_used'] : null,
                'scopes' => preg_split('/\s+/', trim((string)($row['scopes'] ?? ''))) ?: [],
                'app_name' => $row['app_name'] ?: 'Unknown app',
                'app_website' => $row['app_website'] ?: null,
                'token_hint' => substr($token, 0, 8) . '…' . substr($token, -4),
            ];
        }, $rows));
    }

    public function delete(array $p): void
    {
        $user = require_auth(['write', 'write:accounts']);
        $currentToken = (string)((auth_context()['token']['token'] ?? '') ?: '');
        $tokenId = (string)($p['id'] ?? '');
        $body = req_body();
        $scope = (string)($body['scope'] ?? '');

        if ($tokenId !== '') {
            $row = DB::one('SELECT token FROM oauth_tokens WHERE token=? AND user_id=?', [$tokenId, $user['id']]);
            if (!$row) err_out('Not found', 404);
            DB::delete('oauth_tokens', 'token=? AND user_id=?', [$tokenId, $user['id']]);
            json_out(['revoked' => 1, 'current' => hash_equals($currentToken, $tokenId)]);
        }

        if ($scope === 'others') {
            if ($currentToken !== '') {
                $count = DB::count('oauth_tokens', 'user_id=? AND token<>?', [$user['id'], $currentToken]);
                DB::delete('oauth_tokens', 'user_id=? AND token<>?', [$user['id'], $currentToken]);
            } else {
                $count = DB::count('oauth_tokens', 'user_id=?', [$user['id']]);
                DB::delete('oauth_tokens', 'user_id=?', [$user['id']]);
            }
            json_out(['revoked' => $count, 'current' => false]);
        }

        if ($scope === 'current') {
            if ($currentToken === '') err_out('No current token', 422);
            DB::delete('oauth_tokens', 'token=? AND user_id=?', [$currentToken, $user['id']]);
            json_out(['revoked' => 1, 'current' => true]);
        }

        err_out('Nothing to revoke', 422);
    }
}

class DeveloperAppsCtrl
{
    private function fmtToken(array $row): array
    {
        $token = (string)($row['token'] ?? '');
        return [
            'id' => $token,
            'app_id' => (string)($row['app_id'] ?? ''),
            'app_name' => (string)($row['app_name'] ?? 'Unknown app'),
            'created_at' => (string)($row['created_at'] ?? ''),
            'last_used_at' => ($row['last_used'] ?? '') !== '' ? (string)$row['last_used'] : null,
            'scopes' => preg_split('/\s+/', trim((string)($row['scopes'] ?? ''))) ?: [],
            'token_hint' => $token !== '' ? substr($token, 0, 8) . '…' . substr($token, -4) : '',
        ];
    }

    public function index(array $p): void
    {
        $user = require_auth('read');
        $apps = array_map(static fn(array $app): array => OAuthModel::appToMasto($app), OAuthModel::appsByOwner($user['id']));
        $tokens = DB::all(
            'SELECT t.token, t.app_id, t.scopes, t.created_at, t.last_used, a.name AS app_name
               FROM oauth_tokens t
               JOIN oauth_apps a ON a.id=t.app_id
              WHERE t.user_id=? AND a.owner_user_id=?
           ORDER BY COALESCE(NULLIF(t.last_used, \'\'), t.created_at) DESC',
            [$user['id'], $user['id']]
        );
        json_out([
            'apps' => $apps,
            'tokens' => array_map([$this, 'fmtToken'], $tokens),
        ]);
    }

    public function create(array $p): void
    {
        $user = require_auth(['write', 'write:filters']);
        $d = req_body();
        $clientName = trim((string)($d['client_name'] ?? ''));
        if ($clientName === '') err_out('Application name required', 422);
        $requestedScopes = (string)($d['scopes'] ?? $d['scope'] ?? 'read write follow');
        $scopes = OAuthModel::normalizeScopes($requestedScopes);
        if ($scopes === '') err_out('invalid_scope', 422);
        $app = OAuthModel::createApp([
            'owner_user_id' => $user['id'],
            'client_name' => $clientName,
            'website' => trim((string)($d['website'] ?? '')),
            'redirect_uris' => trim((string)($d['redirect_uris'] ?? $d['redirect_uri'] ?? 'urn:ietf:wg:oauth:2.0:oob')),
            'scopes' => $scopes,
        ]);
        json_out(OAuthModel::appToMasto($app), 201);
    }

    public function delete(array $p): void
    {
        $user = require_auth(['write', 'write:filters']);
        $appId = (string)($p['id'] ?? '');
        $app = OAuthModel::appById($appId);
        if (!$app || (string)($app['owner_user_id'] ?? '') !== $user['id']) err_out('Not found', 404);
        OAuthModel::deleteApp($appId, $user['id']);
        json_out(['deleted' => true]);
    }

    public function createToken(array $p): void
    {
        $user = require_auth(['write', 'write:filters']);
        $appId = (string)($p['id'] ?? '');
        $app = OAuthModel::appById($appId);
        if (!$app || (string)($app['owner_user_id'] ?? '') !== $user['id']) err_out('Not found', 404);
        $d = req_body();
        $scopes = OAuthModel::normalizeScopes((string)($d['scopes'] ?? $d['scope'] ?? ''), (string)($app['scopes'] ?? ''));
        if ($scopes === '') err_out('invalid_scope', 422);
        $token = OAuthModel::createToken($appId, $user['id'], $scopes);
        json_out([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'scope' => $scopes,
            'created_at' => time(),
            'app' => OAuthModel::appToMasto($app),
        ], 201);
    }

    public function revokeToken(array $p): void
    {
        $user = require_auth(['write', 'write:filters']);
        $token = (string)($p['token'] ?? '');
        $row = DB::one(
            'SELECT t.token
               FROM oauth_tokens t
               JOIN oauth_apps a ON a.id=t.app_id
              WHERE t.token=? AND t.user_id=? AND a.owner_user_id=?',
            [$token, $user['id'], $user['id']]
        );
        if (!$row) err_out('Not found', 404);
        DB::delete('oauth_tokens', 'token=?', [$token]);
        json_out(['revoked' => true]);
    }
}

class FollowsCsvCtrl
{
    public function export(array $p): void
    {
        $user = require_auth('read');
        $type = (string)($_GET['type'] ?? 'following');
        if (!in_array($type, ['following', 'followers'], true)) err_out('Invalid export type', 422);

        if ($type === 'following') {
            $rows = DB::all(
                'SELECT following_id AS target_id, notify FROM follows WHERE follower_id=? AND pending=0 ORDER BY created_at DESC',
                [$user['id']]
            );
        } else {
            $rows = DB::all(
                'SELECT follower_id AS target_id, 0 AS notify FROM follows WHERE following_id=? AND pending=0 ORDER BY created_at DESC',
                [$user['id']]
            );
        }

        $lines = ["Account address,Show boosts,Notify on new posts,Languages"];
        foreach ($rows as $row) {
            $targetId = (string)($row['target_id'] ?? '');
            if ($targetId === '') continue;
            $local = UserModel::byId($targetId);
            if ($local) {
                if (!empty($local['is_suspended'])) continue;
                $acct = $local['username'] . '@' . AP_DOMAIN;
            } else {
                $remote = DB::one('SELECT username, domain FROM remote_actors WHERE id=?', [$targetId]);
                if (!$remote) continue;
                $acct = $remote['username'] . '@' . $remote['domain'];
            }
            $notify = !empty($row['notify']) ? 'true' : 'false';
            $lines[] = '"' . str_replace('"', '""', $acct) . '",true,' . $notify . ',';
        }

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . ($type === 'following' ? 'following' : 'followers') . '.csv"');
        echo implode("\r\n", $lines) . "\r\n";
        exit;
    }
}

class AccountLifecycleCtrl
{
    public function delete(array $p): void
    {
        $user = require_auth(['write', 'write:filters']);
        $d = req_body();
        $password = (string)($d['current_password'] ?? '');
        if ($password === '' || !password_verify($password, (string)($user['password'] ?? ''))) {
            err_out('Invalid password', 422);
        }

        if (!empty($user['is_admin'])) {
            $admins = DB::count('users', 'is_admin=1 AND is_suspended=0');
            if ($admins <= 1) err_out('Cannot delete the last administrator account', 422);
        }

        AdminModel::deleteUser($user['id']);
        json_out(['deleted' => true]);
    }
}

// ── Announcements ─────────────────────────────────────────────

class AnnouncementsCtrl
{
    public function index(array $p): void
    {
        require_auth('read');
        json_out(AnnouncementsModel::visible());
    }
}

// ── Filters (v1 + v2) ────────────────────────────────────────

class FiltersCtrl
{
    private const ALLOWED_CONTEXTS = ['home', 'notifications', 'public', 'thread', 'account'];
    private const ALLOWED_ACTIONS  = ['warn', 'hide'];

    private function isV1(): bool
    {
        $path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
        return str_starts_with($path, '/api/v1/filters');
    }

    private function normalizeContext(mixed $context): array
    {
        $items = is_array($context) ? $context : [];
        $out = [];
        foreach ($items as $item) {
            $value = strtolower(trim((string)$item));
            if ($value === '' || !in_array($value, self::ALLOWED_CONTEXTS, true)) continue;
            if (!in_array($value, $out, true)) $out[] = $value;
        }
        return $out;
    }

    private function normalizeAction(array $d): string
    {
        $action = isset($d['filter_action'])
            ? strtolower(trim((string)$d['filter_action']))
            : (bool_val($d['irreversible'] ?? false) ? 'hide' : 'warn');
        return in_array($action, self::ALLOWED_ACTIONS, true) ? $action : 'warn';
    }

    private function fmt(array $f): array
    {
        $keywords = DB::all('SELECT * FROM filter_keywords WHERE filter_id=?', [$f['id']]);
        $context = json_decode($f['context'], true) ?: [];
        $keywordRows = array_map(fn($k) => [
            'id'         => $k['id'],
            'keyword'    => $k['keyword'],
            'whole_word' => (bool)$k['whole_word'],
        ], $keywords);

        if ($this->isV1()) {
            $primary = $keywordRows[0] ?? ['keyword' => '', 'whole_word' => false];
            return [
                'id'           => $f['id'],
                'phrase'       => $primary['keyword'],
                'context'      => $context,
                'expires_at'   => $f['expires_at'],
                'irreversible' => ($f['action'] ?? 'warn') !== 'warn',
                'whole_word'   => (bool)$primary['whole_word'],
            ];
        }

        return [
            'id'          => $f['id'],
            'title'       => $f['title'],
            'context'     => $context,
            'expires_at'  => $f['expires_at'],
            'filter_action' => $f['action'],
            'keywords'    => $keywordRows,
            'statuses'    => [],
        ];
    }

    private function normalizeKeywords(array $d): array
    {
        if (!empty($d['keywords_attributes']) && is_array($d['keywords_attributes'])) {
            $seen = [];
            $out = [];
            foreach ($d['keywords_attributes'] as $kw) {
                if (!is_array($kw)) continue;
                $keyword = trim((string)($kw['keyword'] ?? ''));
                if ($keyword === '') continue;
                $key = mb_strtolower($keyword, 'UTF-8');
                if (isset($seen[$key])) continue;
                $seen[$key] = true;
                $out[] = [
                    'keyword'    => $keyword,
                    'whole_word' => bool_val($kw['whole_word'] ?? false),
                    '_destroy'   => bool_val($kw['_destroy'] ?? false),
                ];
            }
            return $out;
        }

        $phrase = trim((string)($d['phrase'] ?? ''));
        if ($phrase === '') return [];

        return [[
            'keyword'    => $phrase,
            'whole_word' => bool_val($d['whole_word'] ?? false),
        ]];
    }

    public function index(array $p): void
    {
        $user = require_auth('read');
        $rows = DB::all('SELECT * FROM filters WHERE user_id=? ORDER BY created_at DESC', [$user['id']]);
        json_out(array_map([$this, 'fmt'], $rows));
    }

    public function show(array $p): void
    {
        $user = require_auth('read');
        $f = DB::one('SELECT * FROM filters WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$f) err_out('Not found', 404);
        json_out($this->fmt($f));
    }

    public function create(array $p): void
    {
        $user = require_auth(['write', 'write:filters']);
        $d    = req_body();
        $id   = uuid(); $now = now_iso();
        $keywords = $this->normalizeKeywords($d);
        $action = $this->normalizeAction($d);
        $context = $this->normalizeContext($d['context'] ?? []);
        if (!$keywords) err_out('At least one keyword required', 422);
        if (!$context) err_out('At least one valid context required', 422);

        DB::insert('filters', [
            'id'        => $id,
            'user_id'   => $user['id'],
            'title'     => $d['title'] ?? ($keywords[0]['keyword'] ?? ''),
            'context'   => json_encode($context),
            'action'    => $action,
            'expires_at'=> ($d['expires_in'] ?? null) ? gmdate('Y-m-d\TH:i:s\Z', time() + (int)$d['expires_in']) : null,
            'created_at'=> $now,
        ]);

        foreach ($keywords as $kw) {
            DB::insert('filter_keywords', [
                'id'         => uuid(),
                'filter_id'  => $id,
                'keyword'    => $kw['keyword'] ?? '',
                'whole_word' => (int)bool_val($kw['whole_word'] ?? false),
            ]);
        }

        json_out($this->fmt(DB::one('SELECT * FROM filters WHERE id=?', [$id])));
    }

    public function update(array $p): void
    {
        $user = require_auth(['write', 'write:accounts']);
        $f    = DB::one('SELECT * FROM filters WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$f) err_out('Not found', 404);
        $d = req_body();
        $keywords = $this->normalizeKeywords($d);

        $upd = [];
        if (isset($d['title']))         $upd['title']   = $d['title'];
        if (isset($d['context'])) {
            $context = $this->normalizeContext($d['context']);
            if (!$context) err_out('At least one valid context required', 422);
            $upd['context'] = json_encode($context);
        }
        if (isset($d['filter_action']) || array_key_exists('irreversible', $d)) {
            $upd['action'] = $this->normalizeAction($d);
        }
        if (isset($d['expires_in']))    $upd['expires_at'] = $d['expires_in']
            ? gmdate('Y-m-d\TH:i:s\Z', time() + (int)$d['expires_in']) : null;
        if ($upd) DB::update('filters', $upd, 'id=?', [$p['id']]);

        // Replace keywords if provided
        if (isset($d['keywords_attributes']) || array_key_exists('phrase', $d)) {
            $keptKeywords = array_values(array_filter($keywords, fn(array $kw) => empty($kw['_destroy'])));
            if (!$keptKeywords) err_out('At least one keyword required', 422);
            DB::delete('filter_keywords', 'filter_id=?', [$p['id']]);
            foreach ($keptKeywords as $kw) {
                if (!empty($kw['_destroy'])) continue;
                DB::insert('filter_keywords', [
                    'id'         => uuid(),
                    'filter_id'  => $p['id'],
                    'keyword'    => $kw['keyword'] ?? '',
                    'whole_word' => (int)bool_val($kw['whole_word'] ?? false),
                ]);
            }
        }

        json_out($this->fmt(DB::one('SELECT * FROM filters WHERE id=?', [$p['id']])));
    }

    public function delete(array $p): void
    {
        $user = require_auth(['write', 'write:filters']);
        $f = DB::one('SELECT id FROM filters WHERE id=? AND user_id=?', [$p['id'], $user['id']]);
        if (!$f) err_out('Not found', 404);
        DB::delete('filter_keywords', 'filter_id=?', [$p['id']]);
        DB::delete('filters', 'id=?', [$p['id']]);
        json_out([]);
    }
}

// ── User-level domain blocks ──────────────────────────────────

class UserDomainBlocksCtrl
{
    public function index(array $p): void
    {
        $user  = require_auth('read');
        $rows  = DB::all('SELECT domain FROM user_domain_blocks WHERE user_id=? ORDER BY domain', [$user['id']]);
        json_out(array_column($rows, 'domain'));
    }

    public function create(array $p): void
    {
        $user   = require_auth(['write', 'write:blocks']);
        $d      = req_body();
        $domain = strtolower(trim($d['domain'] ?? ''));
        if (!$domain) err_out('domain required', 422);
        DB::insertIgnore('user_domain_blocks', [
            'id'         => uuid(),
            'user_id'    => $user['id'],
            'domain'     => $domain,
            'created_at' => now_iso(),
        ]);
        json_out([]);
    }

    public function delete(array $p): void
    {
        $user   = require_auth(['write', 'write:blocks']);
        $domain = strtolower(trim(req_body()['domain'] ?? $_GET['domain'] ?? ''));
        if (!$domain) err_out('domain required', 422);
        DB::delete('user_domain_blocks', 'user_id=? AND domain=?', [$user['id'], $domain]);
        json_out([]);
    }
}

// ── Follow suggestions ────────────────────────────────────────

class SuggestionsCtrl
{
    private function suggest(int $limit): array
    {
        $user = require_auth('read');
        $uid  = $user['id'];
        $blocked = StatusModel::blockedDomains($uid);

        // Local users (excluding self and already-followed)
        $locals = DB::all(
            "SELECT *, 'local' AS _src FROM users
             WHERE id != ? AND is_suspended = 0 AND is_bot = 0 AND discoverable = 1
               AND id NOT IN (SELECT following_id FROM follows WHERE follower_id=?)
               AND id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
               AND id NOT IN (SELECT target_id FROM mutes WHERE user_id=?)
             ORDER BY follower_count DESC LIMIT ?",
            [$uid, $uid, $uid, $uid, $limit]
        );

        $need = $limit - count($locals);
        $remotes = [];
        if ($need > 0) {
            // Remote actors not yet followed, ordered by follower_count
            $sql = "SELECT *, 'remote' AS _src FROM remote_actors
                    WHERE id NOT IN (SELECT following_id FROM follows WHERE follower_id=?)
                      AND id NOT IN (SELECT target_id FROM blocks WHERE user_id=?)
                      AND id NOT IN (SELECT target_id FROM mutes WHERE user_id=?)
                      AND username != '' AND domain != '' AND is_bot = 0";
            $params = [$uid, $uid, $uid];
            if ($blocked) {
                $sql .= ' AND LOWER(domain) NOT IN (' . implode(',', array_fill(0, count($blocked), '?')) . ')';
                array_push($params, ...$blocked);
            }
            $sql .= ' ORDER BY follower_count DESC LIMIT ?';
            $params[] = $need;
            $remotes = DB::all($sql, $params);
        }

        return array_merge($locals, $remotes);
    }

    // GET /api/v2/suggestions — returns [{source, account}]
    public function index(array $p): void
    {
        $limit = max(1, min((int)($_GET['limit'] ?? 40), 40));
        $rows  = $this->suggest($limit);
        json_out(array_values(array_filter(array_map(function ($u) {
            $account = ($u['_src'] ?? 'local') === 'remote'
                ? UserModel::remoteToMasto($u)
                : UserModel::toMasto($u);
            if (!$account) return null;
            return ['source' => 'global', 'account' => $account];
        }, $rows))));
    }

    // GET /api/v1/follow_suggestions — returns [account] (formato v1)
    public function indexV1(array $p): void
    {
        $limit = max(1, min((int)($_GET['limit'] ?? 40), 40));
        $rows  = $this->suggest($limit);
        json_out(array_values(array_filter(array_map(function ($u) {
            $account = ($u['_src'] ?? 'local') === 'remote'
                ? UserModel::remoteToMasto($u)
                : UserModel::toMasto($u);
            return $account ?: null;
        }, $rows))));
    }

    public function delete(array $p): void
    {
        require_auth(['write', 'write:accounts']);
        json_out([]);
    }
}

// ── Account lookup ────────────────────────────────────────────

class AccountLookupCtrl
{
    public function show(array $p): void
    {
        $viewer = authed_user();
        $viewerId = $viewer['id'] ?? null;
        $acct = trim($_GET['acct'] ?? '');
        if (!$acct) err_out('acct required', 422);

        $acct = ltrim($acct, '@');

        if (str_contains($acct, '@')) {
            [$username, $domain] = $this->splitLookupAcct($acct);
            if (is_local($domain)) {
                $u = UserModel::byUsername($username);
                if ($u && !$this->isHiddenFromViewer($viewerId, $u['id'])) { json_out(UserModel::toMasto($u)); }
                err_out('Not found', 404); // Don't attempt remote lookup for our own domain
            }
            if ($viewerId && in_array(strtolower($domain), StatusModel::blockedDomains($viewerId), true)) {
                err_out('Not found', 404);
            }
            // Remote lookup
            $ra = \App\Models\RemoteActorModel::fetchByAcct($username, $domain);
            if ($ra && !$this->isHiddenFromViewer($viewerId, $ra['id'], $ra['domain'] ?? null)) json_out(UserModel::remoteToMasto($ra));
        } else {
            $u = UserModel::byUsername($acct);
            if ($u && !$this->isHiddenFromViewer($viewerId, $u['id'])) json_out(UserModel::toMasto($u));
        }

        err_out('Not found', 404);
    }

    private function splitLookupAcct(string $acct): array
    {
        $parts = explode('@', ltrim(trim($acct), '@'));
        $domain = strtolower((string)array_pop($parts));
        $username = implode('@', $parts);

        $duplicateSuffix = '@' . $domain;
        if ($domain !== '' && str_ends_with(strtolower($username), $duplicateSuffix)) {
            $username = substr($username, 0, -strlen($duplicateSuffix));
        }

        return [$username, $domain];
    }

    private function isHiddenFromViewer(?string $viewerId, string $targetId, ?string $domain = null): bool
    {
        if (!$viewerId) {
            return false;
        }
        if (DB::one('SELECT 1 FROM blocks WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) {
            return true;
        }
        if (DB::one('SELECT 1 FROM mutes WHERE user_id=? AND target_id=?', [$viewerId, $targetId])) {
            return true;
        }
        if ($domain !== null && in_array(strtolower($domain), StatusModel::blockedDomains($viewerId), true)) {
            return true;
        }
        return false;
    }
}

// ── Featured tags ─────────────────────────────────────────────

class FeaturedTagsCtrl
{
    public function index(array $p): void
    {
        $user = require_auth('read');
        $rows = DB::all('SELECT * FROM featured_tags WHERE user_id=?', [$user['id']]);
        json_out(array_map([$this, 'fmt'], $rows));
    }

    public function create(array $p): void
    {
        $user = require_auth(['write', 'write:accounts']);
        $d    = req_body();
        $name = mb_strtolower(ltrim(trim((string)($d['name'] ?? '')), '#'), 'UTF-8');
        if (!$name) err_out('name required', 422);
        $id = uuid();
        DB::insertIgnore('featured_tags', [
            'id' => $id, 'user_id' => $user['id'], 'name' => $name, 'created_at' => now_iso()
        ]);
        // Fetch by (user_id, name) — if insert was ignored due to UNIQUE(user_id,name),
        // the new $id was never inserted and a lookup by $id would return null.
        $tag = DB::one('SELECT * FROM featured_tags WHERE user_id=? AND name=?', [$user['id'], $name]);
        if (!$tag) err_out('Failed to create featured tag', 500);
        json_out($this->fmt($tag));
    }

    public function delete(array $p): void
    {
        $user = require_auth(['write', 'write:accounts']);
        DB::delete('featured_tags', 'id=? AND user_id=?', [$p['id'], $user['id']]);
        json_out([]);
    }

    private function fmt(array $r): array
    {
        $since = gmdate('Y-m-d\TH:i:s\Z', strtotime('-7 days'));
        $count = DB::count(
            'status_hashtags sh JOIN hashtags h ON h.id=sh.hashtag_id JOIN statuses s ON s.id=sh.status_id',
            "h.name=? AND s.user_id=? AND s.created_at>? AND s.visibility IN ('public','unlisted')
             AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)",
            [$r['name'], $r['user_id'], $since, now_iso()]
        );
        $last = DB::one(
            'SELECT MAX(s.created_at) last FROM status_hashtags sh
             JOIN hashtags h ON h.id=sh.hashtag_id
             JOIN statuses s ON s.id=sh.status_id
             WHERE h.name=? AND s.user_id=? AND s.visibility IN (\'public\',\'unlisted\')
               AND (s.expires_at IS NULL OR s.expires_at=\'\' OR s.expires_at>?)',
            [$r['name'], $r['user_id'], now_iso()]
        );
        return [
            'id'              => $r['id'],
            'name'            => $r['name'],
            'url'             => ap_url('tags/' . rawurlencode($r['name'])),
            'statuses_count'  => $count,
            'last_status_at'  => $last['last'] ?? null,
        ];
    }
}


// ── Account Featured Tags (public view) ──────────────────────

class AccountFeaturedTagsCtrl
{
    public function show(array $p): void
    {
        // Public featured tags for any account (no auth required)
        $accountId = (string)$p['id'];
        $owner = UserModel::byId($accountId);
        if (!$owner || !empty($owner['is_suspended'])) {
            $remote = DB::one('SELECT id FROM remote_actors WHERE masto_id=?', [$accountId]);
            if ($remote) {
                json_out([]);
            }
            err_out('Not found', 404);
        }
        $rows = DB::all('SELECT * FROM featured_tags WHERE user_id=?', [$accountId]);
        // p['id'] could be local user id — map directly
        json_out(array_map(function ($r) {
            $since = gmdate('Y-m-d\\TH:i:s\\Z', strtotime('-7 days'));
            $count = DB::count(
                'status_hashtags sh JOIN hashtags h ON h.id=sh.hashtag_id JOIN statuses s ON s.id=sh.status_id',
                "h.name=? AND s.user_id=? AND s.created_at>? AND s.visibility IN ('public','unlisted')
                 AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)",
                [$r['name'], $r['user_id'], $since, now_iso()]
            );
            $last = DB::one(
                'SELECT MAX(s.created_at) last FROM status_hashtags sh
                 JOIN hashtags h ON h.id=sh.hashtag_id
                 JOIN statuses s ON s.id=sh.status_id
                 WHERE h.name=? AND s.user_id=? AND s.visibility IN (\'public\',\'unlisted\')
                   AND (s.expires_at IS NULL OR s.expires_at=\'\' OR s.expires_at>?)',
                [$r['name'], $r['user_id'], now_iso()]
            );
            return [
                'id'             => $r['id'],
                'name'           => $r['name'],
                'url'            => ap_url('tags/' . rawurlencode($r['name'])),
                'statuses_count' => $count,
                'last_status_at' => $last['last'] ?? null,
            ];
        }, $rows));
    }
}

// ── Featured Tags Suggestions ─────────────────────────────────

class FeaturedTagsSuggestionsCtrl
{
    public function index(array $p): void
    {
        $user = require_auth('read');
        // Suggest hashtags the user has used most in last 30 days
        $since = gmdate('Y-m-d\\TH:i:s\\Z', strtotime('-30 days'));
        $rows = DB::all(
            "SELECT h.id,
                    h.name,
                    COUNT(*) as cnt,
                    MAX(CASE WHEN tf.user_id IS NOT NULL THEN 1 ELSE 0 END) AS following
             FROM status_hashtags sh
             JOIN hashtags h ON h.id=sh.hashtag_id
             JOIN statuses s ON s.id=sh.status_id
             LEFT JOIN tag_follows tf ON tf.hashtag_id=h.id AND tf.user_id=?
             LEFT JOIN featured_tags ft ON ft.user_id=? AND ft.name=h.name
             WHERE s.user_id=? AND s.created_at>?
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
               AND ft.id IS NULL
             GROUP BY h.id, h.name ORDER BY cnt DESC LIMIT 10",
            [$user['id'], $user['id'], $user['id'], $since, now_iso()]
        );
        json_out(array_map(fn($r) => [
            'id'        => $r['id'],
            'name'      => $r['name'],
            'url'       => ap_url('tags/' . rawurlencode($r['name'])),
            'history'   => [],
            'following' => (bool)($r['following'] ?? 0),
        ], $rows));
    }
}

// ── Hashtag follow API ────────────────────────────────────────

class TagsApiCtrl
{
    private function tagObject(string $name, ?string $userId = null): array
    {
        $name = mb_strtolower(ltrim(trim($name), '#'), 'UTF-8');
        $url       = ap_url('tags/' . rawurlencode($name));
        $tagId     = null;
        $following = false;
        $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$name]);
        if ($ht) {
            $tagId = $ht['id'];
            if ($userId) {
                $following = (bool)DB::one('SELECT 1 FROM tag_follows WHERE user_id=? AND hashtag_id=?', [$userId, $ht['id']]);
            }
        }
        return [
            'id'        => $tagId,
            'name'      => $name,
            'url'       => $url,
            'history'   => self::tagHistory($name, $userId),
            'following' => $following,
        ];
    }

    private static function tagHistory(string $name, ?string $userId = null): array
    {
        $since = gmdate('Y-m-d', strtotime('-6 days')) . 'T00:00:00Z';
        $domainFilter = StatusModel::domainBlockSql('s.user_id', StatusModel::blockedDomains($userId));
        $rows  = DB::all(
            "SELECT strftime('%Y-%m-%d', s.created_at) day,
                    COUNT(*) uses,
                    COUNT(DISTINCT s.user_id) accounts
             FROM status_hashtags sh
             JOIN hashtags h ON h.id = sh.hashtag_id
             JOIN statuses s ON s.id = sh.status_id
            WHERE h.name = ? AND s.created_at >= ? AND s.visibility IN ('public','unlisted')
              AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
              $domainFilter
             GROUP BY day",
            [mb_strtolower($name, 'UTF-8'), $since]
        );
        // Index by date for fast lookup
        $byDay = [];
        foreach ($rows as $r) {
            $byDay[$r['day']] = $r;
        }
        $out = [];
        for ($i = 0; $i < 7; $i++) {
            $day   = gmdate('Y-m-d', strtotime("-$i days"));
            $r     = $byDay[$day] ?? null;
            $out[] = [
                'day'      => (string)strtotime($day . 'T00:00:00Z'),
                'uses'     => (string)($r['uses'] ?? 0),
                'accounts' => (string)($r['accounts'] ?? 0),
            ];
        }
        return $out;
    }

    public function show(array $p): void
    {
        $user = authed_user();
        $name = ltrim((string)($p['name'] ?? ''), '#');
        json_out($this->tagObject($name, $user['id'] ?? null));
    }

    public function follow(array $p): void
    {
        $user = require_auth(['follow', 'write', 'write:follows']);
        $name = mb_strtolower(ltrim((string)($p['name'] ?? ''), '#'), 'UTF-8');
        if (!$name) err_out('tag name required', 422);

        $ht = DB::one('SELECT id FROM hashtags WHERE name=?', [$name]);
        if (!$ht) {
            $htId = uuid();
            DB::insert('hashtags', ['id' => $htId, 'name' => $name, 'created_at' => now_iso()]);
            $ht = ['id' => $htId];
        }

        DB::insertIgnore('tag_follows', [
            'id'         => uuid(),
            'user_id'    => $user['id'],
            'hashtag_id' => $ht['id'],
            'created_at' => now_iso(),
        ]);
        json_out($this->tagObject($p['name'], $user['id']));
    }

    public function unfollow(array $p): void
    {
        $user = require_auth(['follow', 'write', 'write:follows']);
        $name = mb_strtolower(ltrim((string)($p['name'] ?? ''), '#'), 'UTF-8');
        $ht   = DB::one('SELECT id FROM hashtags WHERE name=?', [$name]);
        if ($ht) {
            DB::delete('tag_follows', 'user_id=? AND hashtag_id=?', [$user['id'], $ht['id']]);
        }
        json_out($this->tagObject($name, $user['id']));
    }
}
