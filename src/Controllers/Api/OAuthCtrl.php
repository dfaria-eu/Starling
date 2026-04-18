<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{OAuthModel, UserModel};

class OAuthCtrl
{
    private function startSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_name('ap_oauth');
            session_set_cookie_params([
                'path' => '/',
                'secure' => is_https_request(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            session_start();
        }
    }

    private function clientCredentials(array $body): array
    {
        $clientId     = (string)($body['client_id'] ?? '');
        $clientSecret = (string)($body['client_secret'] ?? '');

        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (($clientId === '' || $clientSecret === '') && preg_match('/^Basic\s+(.+)$/i', $auth, $m)) {
            $decoded = base64_decode($m[1], true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$basicId, $basicSecret] = explode(':', $decoded, 2);
                if ($clientId === '')     $clientId = $basicId;
                if ($clientSecret === '') $clientSecret = $basicSecret;
            }
        }

        return [$clientId, $clientSecret];
    }

    private function redirectUriAllowed(array $app, string $redir): bool
    {
        $registeredUri = $app['redirect_uri'] ?? '';
        if ($redir === 'urn:ietf:wg:oauth:2.0:oob' || $registeredUri === 'urn:ietf:wg:oauth:2.0:oob') {
            return $redir === $registeredUri || $redir === 'urn:ietf:wg:oauth:2.0:oob';
        }
        $allowed = array_filter(array_map('trim', preg_split('/\R+/', $registeredUri ?: '')));
        return in_array($redir, $allowed, true);
    }

    public function token(array $p): void
    {
        rate_limit_enforce('oauth_token:' . client_ip(), 30, 300, 'Rate limit exceeded for token requests');
        $d     = req_body();
        $grant = $d['grant_type'] ?? '';
        [$clientId, $clientSecret] = $this->clientCredentials($d);

        if ($grant === 'authorization_code') {
            $codeValue = (string)($d['code'] ?? '');
            $code = OAuthModel::codeByValue($codeValue);
            if (!$code) err_out('invalid_grant', 400);

            $app = OAuthModel::appByClientId($clientId);
            if (!$app || $app['id'] !== $code['app_id']) err_out('invalid_client', 401);

            // redirect_uri must match what was used when the code was issued (RFC 6749 §4.1.3)
            $sentUri = $d['redirect_uri'] ?? '';
            if ($code['redirect_uri'] && $sentUri !== $code['redirect_uri']) {
                err_out('invalid_grant: redirect_uri mismatch', 400);
            }

            // PKCE verification (RFC 7636)
            if ($code['code_challenge']) {
                $verifier = $d['code_verifier'] ?? '';
                if (!$verifier) err_out('invalid_grant: code_verifier required', 400);
                $method   = $code['challenge_method'] ?: 'S256';
                if ($method === 'S256') {
                    $expected = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
                } else {
                    $expected = $verifier; // plain
                }
                if (!hash_equals($expected, $code['code_challenge'])) {
                    err_out('invalid_grant: code_verifier mismatch', 400);
                }
            } elseif ($app['client_secret'] !== '' && !hash_equals($app['client_secret'], $clientSecret)) {
                err_out('invalid_client', 401);
            }

            OAuthModel::redeemCode($codeValue);
            $tok = OAuthModel::createToken($code['app_id'], $code['user_id'], $code['scopes']);
            $this->tokenResp($tok, $code['scopes']);
        } elseif ($grant === 'password') {
            $app  = OAuthModel::appByClientCredentials($clientId, $clientSecret);
            if (!$app) err_out('invalid_client', 400);
            $user = UserModel::verify($d['username'] ?? '', $d['password'] ?? '');
            if (!$user) err_out('invalid_grant', 401);
            $scopes = OAuthModel::normalizeScopes($d['scope'] ?? null, $app['scopes']);
            if ($scopes === '') err_out('invalid_scope', 400);
            $tok    = OAuthModel::createToken($app['id'], $user['id'], $scopes);
            $this->tokenResp($tok, $scopes);
        } elseif ($grant === 'client_credentials') {
            $app = OAuthModel::appByClientCredentials($clientId, $clientSecret);
            if (!$app) err_out('invalid_client', 400);
            $scopes = OAuthModel::normalizeScopes($d['scope'] ?? 'read', $app['scopes']);
            if ($scopes === '') err_out('invalid_scope', 400);
            $tok = OAuthModel::createToken($app['id'], '', $scopes);
            $this->tokenResp($tok, $scopes);
        } else {
            err_out('unsupported_grant_type', 400);
        }
    }

    private function tokenResp(string $tok, string $scopes): never
    {
        json_out([
            'access_token' => $tok,
            'token_type'   => 'Bearer',
            'scope'        => $scopes,
            'created_at'   => time(),
            'expires_in'   => 315360000, // ~10 years — tokens don't expire unless revoked
        ]);
    }

    public function authorizeForm(array $p): void
    {
        $clientId        = $_GET['client_id'] ?? '';
        $redir           = $_GET['redirect_uri'] ?? 'urn:ietf:wg:oauth:2.0:oob';
        $scope           = $_GET['scope'] ?? 'read write follow push';
        $state           = $_GET['state'] ?? '';
        $codeChallenge   = $_GET['code_challenge'] ?? '';
        $challengeMethod = $_GET['code_challenge_method'] ?? 'S256';
        if (!in_array($challengeMethod, ['S256', 'plain'], true)) $challengeMethod = 'S256';
        $app             = OAuthModel::appByClientId($clientId);
        if (!$app) err_out('Invalid client', 400);
        if (!$this->redirectUriAllowed($app, $redir)) err_out('redirect_uri mismatch', 400);
        $scope = OAuthModel::normalizeScopes($scope, $app['scopes']);
        if ($scope === '') err_out('invalid_scope', 400);

        $this->startSession();
        $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16));

        header('Content-Type: text/html; charset=utf-8');
        echo $this->form($app, $redir, $scope, '', $state, $codeChallenge, $challengeMethod, $_SESSION['oauth_csrf']);
        exit;
    }

    public function authorizeSubmit(array $p): void
    {
        $this->startSession();
        $d        = $_POST;
        $clientId = $d['client_id'] ?? '';
        $redir    = $d['redirect_uri'] ?? 'urn:ietf:wg:oauth:2.0:oob';
        $scope    = $d['scope'] ?? 'read';
        $app      = OAuthModel::appByClientId($clientId);
        if (!$app) err_out('Invalid client', 400);
        $scope    = OAuthModel::normalizeScopes($scope, $app['scopes']);
        if ($scope === '') err_out('invalid_scope', 400);

        $state           = $d['state'] ?? '';
        $codeChallenge   = $d['code_challenge'] ?? '';
        $challengeMethod = $d['code_challenge_method'] ?? 'S256';
        if (!in_array($challengeMethod, ['S256', 'plain'], true)) $challengeMethod = 'S256';
        $csrf = (string)($d['csrf'] ?? '');
        $sessionCsrf = (string)($_SESSION['oauth_csrf'] ?? '');
        if ($sessionCsrf === '' || $csrf === '' || !hash_equals($sessionCsrf, $csrf)) {
            $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16));
            header('Content-Type: text/html; charset=utf-8');
            echo $this->form($app, $redir, $scope, 'Session expired. Please authorize again.', $state, $codeChallenge, $challengeMethod, $_SESSION['oauth_csrf']);
            exit;
        }

        // Validate redirect_uri against registered app URI (RFC 6749 §4.1.2 / open-redirect prevention)
        if (!$this->redirectUriAllowed($app, $redir)) err_out('redirect_uri mismatch', 400);

        $user = UserModel::verify($d['username'] ?? '', $d['password'] ?? '');
        if (!$user) {
            $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16));
            header('Content-Type: text/html; charset=utf-8');
            echo $this->form($app, $redir, $scope, 'Invalid credentials.', $state, $codeChallenge, $challengeMethod, $_SESSION['oauth_csrf']);
            exit;
        }

        $code = OAuthModel::createCode($app['id'], $user['id'], $scope, $redir, $codeChallenge, $challengeMethod);
        $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16));

        if ($redir === 'urn:ietf:wg:oauth:2.0:oob') {
            header('Content-Type: text/html; charset=utf-8');
            $c = htmlspecialchars($code);
            echo "<!DOCTYPE html><html lang=\"en\"><head><meta charset=utf-8><title>Authorization code</title>"
               . "<link rel=\"icon\" href=\"" . htmlspecialchars(\site_favicon_url(), ENT_QUOTES | ENT_HTML5, 'UTF-8') . "\">"
               . "<style>:root{--bg:#fff;--surface:#fff;--blue:#0085FF;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--blue-bg:#E0EDFF}"
               . "@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--blue-bg:#0C1B3A}}"
               . "body{font-family:'Inter',system-ui,sans-serif;max-width:480px;margin:3rem auto;padding:1rem;background:var(--bg);color:var(--text)}"
               . ".box{background:var(--surface);border:1px solid var(--border);padding:1.5rem;border-radius:12px;text-align:center}"
               . "code{font-size:1.1rem;background:var(--blue-bg);color:var(--blue);padding:.5rem 1rem;border-radius:6px;word-break:break-all}</style></head>"
               . "<body><div class='box'><h2 style='color:var(--blue)'>Authorization code</h2>"
               . "<p>Copy this code into the app:</p><code>$c</code></div></body></html>";
            exit;
        }

        $sep = str_contains($redir, '?') ? '&' : '?';
        $loc = $redir . $sep . 'code=' . urlencode($code);
        if ($state !== '') $loc .= '&state=' . urlencode($state);
        header('Content-Type: text/html; charset=utf-8');
        $safeLoc = htmlspecialchars($loc, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        echo "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
           . "<title>Returning to app</title>"
           . "<link rel=\"icon\" href=\"" . htmlspecialchars(\site_favicon_url(), ENT_QUOTES | ENT_HTML5, 'UTF-8') . "\">"
           . "<meta http-equiv=\"refresh\" content=\"0;url=$safeLoc\">"
           . "<style>:root{--bg:#fff;--surface:#fff;--blue:#0085FF;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--blue-bg:#E0EDFF}"
           . "@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--blue-bg:#0C1B3A}}"
           . "body{font-family:'Inter',system-ui,sans-serif;max-width:520px;margin:3rem auto;padding:1rem;background:var(--bg);color:var(--text)}"
           . ".box{background:var(--surface);border:1px solid var(--border);padding:1.5rem;border-radius:12px;text-align:center}"
           . ".btn{display:inline-block;margin-top:1rem;padding:.8rem 1rem;border-radius:9999px;background:var(--blue);color:#fff;text-decoration:none;font-weight:700}</style>"
           . "</head><body><div class='box'><h2 style='color:var(--blue)'>Authorization granted</h2>"
           . "<p>Returning to the app…</p>"
           . "<p>If nothing happens, use the button below.</p>"
           . "<p><a class='btn' href=\"$safeLoc\">Return to app</a></p>"
           . "<script>location.replace(" . json_encode($loc, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) . ");</script>"
           . "</div></body></html>";
        exit;
    }

    public function revoke(array $p): void
    {
        $d = req_body();
        $ctx = auth_context();
        $currentToken = (string)(($ctx['token']['token'] ?? '') ?: '');
        $token = (string)($d['token'] ?? bearer() ?? $currentToken);
        if ($token === '') err_out('invalid_request', 400);
        OAuthModel::revoke($token);
        json_out([]);
    }

    private function form(array $app, string $redir, string $scope, string $err = '', string $state = '', string $codeChallenge = '', string $challengeMethod = '', string $csrf = ''): string
    {
        $e    = fn($s) => htmlspecialchars((string)$s);
        $errHtml = $err ? '<p class="err">' . $e($err) . '</p>' : '';
        $stateField     = $state           ? '<input type="hidden" name="state" value="' . $e($state) . '">' : '';
        $challengeField = $codeChallenge   ? '<input type="hidden" name="code_challenge" value="' . $e($codeChallenge) . '">' : '';
        $methodField    = $challengeMethod ? '<input type="hidden" name="code_challenge_method" value="' . $e($challengeMethod) . '">' : '';
        $csrfField      = '<input type="hidden" name="csrf" value="' . $e($csrf) . '">';
        return <<<HTML
<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize {$e($app['name'])}</title>
<link rel="icon" href="{$e(\site_favicon_url())}">
<style>
:root{--bg:#fff;--surface:#fff;--hover:#F3F3F8;--blue:#0085FF;--blue2:#0070E0;--blue-bg:#E0EDFF;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--red:#EC4040}
@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--hover:#1E2030;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--blue-bg:#0C1B3A}}
body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;max-width:440px;margin:3rem auto;padding:1rem;background:var(--bg);color:var(--text)}
.card{background:var(--surface);border:1px solid var(--border);padding:2rem;border-radius:12px}
h2{color:var(--blue);margin:0 0 .5rem} .app{font-weight:700}
label{display:block;margin:.8rem 0 .2rem;font-size:.85rem;color:var(--text2)}
input{width:100%;padding:.65rem;background:var(--surface);border:1px solid var(--border);border-radius:9999px;color:var(--text);font-size:1rem;font-family:inherit}
input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-bg)}
button{width:100%;margin-top:1.2rem;padding:.8rem;background:var(--blue);color:#fff;border:0;border-radius:9999px;cursor:pointer;font-size:1rem;font-weight:700;font-family:inherit;transition:background .15s}
button:hover{background:var(--blue2)}
.err{color:var(--red);background:color-mix(in srgb,var(--red) 8%,var(--surface));padding:.5rem .8rem;border-radius:6px;margin:.8rem 0;font-size:.9rem}
.info{color:var(--text2);font-size:.85rem;margin:.5rem 0 1rem}
</style></head><body>
<div class="card">
  <h2>Authorize application</h2>
  <p class="info"><span class="app">{$e($app['name'])}</span> is requesting access to your account on <strong>{$e(AP_DOMAIN)}</strong></p>
  {$errHtml}
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="{$e($app['client_id'])}">
    <input type="hidden" name="redirect_uri" value="{$e($redir)}">
    <input type="hidden" name="scope" value="{$e($scope)}">
    {$stateField}{$challengeField}{$methodField}{$csrfField}
    <label>Username or email</label>
    <input type="text" name="username" required autofocus autocomplete="username">
    <label>Password</label>
    <input type="password" name="password" required autocomplete="current-password">
    <button type="submit">Authorize access</button>
  </form>
</div></body></html>
HTML;
    }
}
