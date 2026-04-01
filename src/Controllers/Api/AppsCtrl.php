<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{OAuthModel, DB};

class AppsCtrl
{
    public function create(array $p): void
    {
        $d = req_body();
        if (empty($d['client_name'])) err_out('client_name required', 422);
        if (array_key_exists('scope', $d) || array_key_exists('scopes', $d)) {
            $requested = (string)($d['scopes'] ?? $d['scope'] ?? '');
            if (trim($requested) !== '' && OAuthModel::normalizeScopes($requested) === '') {
                err_out('invalid_scope', 422);
            }
        }
        $app = OAuthModel::createApp($d);
        json_out(OAuthModel::appToMasto($app));
    }

    /**
     * GET /api/v1/apps/verify_credentials
     * Returns the Application entity for the current bearer token.
     * Used by Mastodon iOS and Ivory to verify the app registration is still valid.
     */
    public function verifyCredentials(array $p): void
    {
        $tok = bearer() ?? ($_GET['access_token'] ?? null);
        if (!$tok) err_out('Unauthorized', 401);

        $row = DB::one('SELECT * FROM oauth_tokens WHERE token=?', [$tok]);
        if (!$row) err_out('Unauthorized', 401);

        $app = DB::one('SELECT * FROM oauth_apps WHERE id=?', [$row['app_id']]);
        if (!$app) err_out('Not found', 404);

        json_out(OAuthModel::appToMasto($app));
    }
}
