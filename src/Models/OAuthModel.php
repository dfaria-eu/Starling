<?php
declare(strict_types=1);

namespace App\Models;

class OAuthModel
{
    public static function normalizeScopes(?string $requested, string $allowed = 'read write follow push'): string
    {
        $allowedList = preg_split('/\s+/', trim($allowed)) ?: [];
        $allowedList = array_values(array_unique(array_filter($allowedList, 'strlen')));
        if (!$allowedList) return '';

        $requestedRaw  = trim((string)$requested);
        $requestedList = preg_split('/\s+/', $requestedRaw) ?: [];
        $requestedList = array_values(array_unique(array_filter($requestedList, 'strlen')));
        if ($requestedRaw === '' || !$requestedList) return implode(' ', $allowedList);

        $effective = array_values(array_intersect($requestedList, $allowedList));
        return $effective ? implode(' ', $effective) : '';
    }

    public static function createApp(array $d): array
    {
        $id = uuid();
        $scopes = self::normalizeScopes($d['scopes'] ?? $d['scope'] ?? 'read write follow push');
        $redirectRaw = $d['redirect_uris'] ?? $d['redirect_uri'] ?? 'urn:ietf:wg:oauth:2.0:oob';
        if (is_array($redirectRaw)) {
            $redirectUris = array_values(array_filter(array_map('trim', $redirectRaw), 'strlen'));
            $redirectUri  = implode("\n", $redirectUris);
        } else {
            $redirectUri = trim((string)$redirectRaw);
        }
        if ($redirectUri === '') $redirectUri = 'urn:ietf:wg:oauth:2.0:oob';
        DB::insert('oauth_apps', [
            'id'            => $id,
            'owner_user_id' => (string)($d['owner_user_id'] ?? ''),
            'name'          => $d['client_name'] ?? 'App',
            'website'       => $d['website'] ?? '',
            'redirect_uri'  => $redirectUri,
            'client_id'     => bin2hex(random_bytes(16)),
            'client_secret' => bin2hex(random_bytes(32)),
            'scopes'        => $scopes,
            'created_at'    => now_iso(),
        ]);
        return DB::one('SELECT * FROM oauth_apps WHERE id=?', [$id]);
    }

    public static function appByClientId(string $cid): ?array
    {
        return DB::one('SELECT * FROM oauth_apps WHERE client_id=?', [$cid]);
    }

    public static function appByClientCredentials(string $cid, string $secret): ?array
    {
        return DB::one('SELECT * FROM oauth_apps WHERE client_id=? AND client_secret=?', [$cid, $secret]);
    }

    public static function appById(string $id): ?array
    {
        return DB::one('SELECT * FROM oauth_apps WHERE id=?', [$id]);
    }

    public static function appsByOwner(string $userId): array
    {
        return DB::all('SELECT * FROM oauth_apps WHERE owner_user_id=? ORDER BY created_at DESC', [$userId]);
    }

    public static function deleteApp(string $appId, string $ownerUserId): void
    {
        DB::delete('oauth_codes', 'app_id=?', [$appId]);
        DB::delete('oauth_tokens', 'app_id=?', [$appId]);
        DB::delete('oauth_apps', 'id=? AND owner_user_id=?', [$appId, $ownerUserId]);
    }

    public static function createCode(string $appId, string $userId, string $scopes, string $redir, string $codeChallenge = '', string $challengeMethod = ''): string
    {
        $code = bin2hex(random_bytes(32));
        DB::insert('oauth_codes', [
            'code'             => $code,
            'app_id'           => $appId,
            'user_id'          => $userId,
            'scopes'           => $scopes,
            'redirect_uri'     => $redir,
            'code_challenge'   => $codeChallenge,
            'challenge_method' => in_array($challengeMethod, ['plain', 'S256'], true) ? $challengeMethod : 'S256',
            'expires_at'       => gmdate('Y-m-d\TH:i:s\Z', time() + 300),
            'created_at'       => now_iso(),
        ]);
        return $code;
    }

    public static function codeByValue(string $code): ?array
    {
        $row = DB::one('SELECT * FROM oauth_codes WHERE code=?', [$code]);
        if (!$row) return null;
        if ($row['expires_at'] < now_iso()) {
            DB::delete('oauth_codes', 'code=?', [$code]);
            return null;
        }
        return $row;
    }

    public static function redeemCode(string $code): ?array
    {
        $row = self::codeByValue($code);
        if (!$row) return null;
        DB::delete('oauth_codes', 'code=?', [$code]);
        return $row;
    }

    public static function createToken(string $appId, string $userId, string $scopes): string
    {
        $tok = bin2hex(random_bytes(32));
        DB::insert('oauth_tokens', [
            'token'      => $tok,
            'app_id'     => $appId,
            'user_id'    => $userId,
            'scopes'     => $scopes,
            'created_at' => now_iso(),
        ]);
        return $tok;
    }

    public static function tokenByValue(string $tok): ?array
    {
        return DB::one('SELECT * FROM oauth_tokens WHERE token=?', [$tok]);
    }

    public static function userByToken(string $tok): ?array
    {
        $row = self::tokenByValue($tok);
        if (!$row || !$row['user_id']) return null;
        DB::update('oauth_tokens', ['last_used' => now_iso()], 'token=?', [$tok]);
        $user = UserModel::byId($row['user_id']);
        if (!$user || !empty($user['is_suspended'])) return null;
        return $user;
    }

    public static function revoke(string $tok): void
    {
        DB::delete('oauth_tokens', 'token=?', [$tok]);
    }

    public static function appToMasto(array $a): array
    {
        $redirectUri = (string)($a['redirect_uri'] ?? '');
        $redirectUris = preg_split('/\s+/', trim($redirectUri)) ?: [];
        $redirectUris = array_values(array_filter($redirectUris, 'strlen'));
        if (!$redirectUris) $redirectUris = ['urn:ietf:wg:oauth:2.0:oob'];

        return [
            'id'            => $a['id'],
            'name'          => $a['name'],
            'website'       => $a['website'] ?: null,
            'scopes'        => preg_split('/\s+/', trim((string)($a['scopes'] ?? ''))) ?: [],
            'redirect_uri'  => $redirectUri !== '' ? $redirectUri : $redirectUris[0],
            'redirect_uris' => $redirectUris,
            'client_id'     => $a['client_id'],
            'client_secret' => $a['client_secret'],
            'client_secret_expires_at' => 0,
            'vapid_key'     => '',
        ];
    }
}
