<?php
declare(strict_types=1);

// ── URL helpers ──────────────────────────────────────────────

function ap_url(string $path = ''): string
{
    return AP_BASE_URL . '/' . ltrim($path, '/');
}

function actor_url(string $username): string
{
    return ap_url('users/' . rawurlencode($username));
}

function absolute_url(string $baseUrl, string $maybeRelative): string
{
    $url = trim($maybeRelative);
    if ($url === '') return '';
    if (preg_match('#^https?://#i', $url)) return $url;

    $parts = parse_url($baseUrl);
    $scheme = $parts['scheme'] ?? 'https';
    $host   = $parts['host'] ?? '';
    if ($host === '') return '';

    if (str_starts_with($url, '//')) {
        return $scheme . ':' . $url;
    }

    $port = isset($parts['port']) ? ':' . $parts['port'] : '';
    $origin = $scheme . '://' . $host . $port;

    if (str_starts_with($url, '/')) {
        return $origin . $url;
    }

    $path = $parts['path'] ?? '/';
    $dir  = preg_replace('#/[^/]*$#', '/', $path) ?: '/';
    $full = $dir . $url;

    $segments = [];
    foreach (explode('/', $full) as $segment) {
        if ($segment === '' || $segment === '.') continue;
        if ($segment === '..') {
            array_pop($segments);
            continue;
        }
        $segments[] = $segment;
    }

    return $origin . '/' . implode('/', $segments);
}

/**
 * Convert an IRI-like URL into an ASCII-safe URI for outbound HTTP requests/cache keys.
 * Preserves already-escaped percent sequences and normal query separators.
 */
function normalize_http_url(string $url): string
{
    $url = trim($url);
    if ($url === '' || !preg_match('#^https?://#i', $url)) return $url;

    $parts = parse_url($url);
    if (!is_array($parts) || empty($parts['host'])) return $url;

    $scheme = strtolower((string)($parts['scheme'] ?? 'https'));
    $host   = (string)$parts['host'];
    if (function_exists('idn_to_ascii') && preg_match('/[^\x20-\x7E]/', $host)) {
        $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if (is_string($ascii) && $ascii !== '') $host = $ascii;
    }

    $userInfo = '';
    if (isset($parts['user'])) {
        $userInfo = rawurlencode((string)$parts['user']);
        if (isset($parts['pass'])) $userInfo .= ':' . rawurlencode((string)$parts['pass']);
        $userInfo .= '@';
    }

    $port = isset($parts['port']) ? ':' . (int)$parts['port'] : '';
    $path = (string)($parts['path'] ?? '');
    $path = preg_replace_callback('/(?:%[0-9A-Fa-f]{2}|[^\/%])+/', static function (array $m): string {
        return rawurlencode(rawurldecode($m[0]));
    }, $path) ?? $path;
    if ($path === '') $path = '/';

    $query = '';
    if (array_key_exists('query', $parts)) {
        $pairs = preg_split('/[&;]/', (string)$parts['query']) ?: [];
        $enc = [];
        foreach ($pairs as $pair) {
            if ($pair === '') continue;
            [$k, $v] = array_pad(explode('=', $pair, 2), 2, null);
            $key = rawurlencode(rawurldecode((string)$k));
            if ($v === null) {
                $enc[] = $key;
            } else {
                $enc[] = $key . '=' . rawurlencode(rawurldecode((string)$v));
            }
        }
        $query = $enc ? '?' . implode('&', $enc) : '';
    }

    $fragment = '';
    if (array_key_exists('fragment', $parts)) {
        $fragment = '#' . rawurlencode(rawurldecode((string)$parts['fragment']));
    }

    return $scheme . '://' . $userInfo . $host . $port . $path . $query . $fragment;
}

function is_local(string $domain): bool
{
    return strtolower(trim($domain)) === strtolower(AP_DOMAIN);
}

function is_https_request(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') return true;
    if (strtolower((string)($_SERVER['REQUEST_SCHEME'] ?? '')) === 'https') return true;
    if ((string)($_SERVER['SERVER_PORT'] ?? '') === '443') return true;
    if (strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') return true;
    if (strtolower((string)($_SERVER['HTTP_X_FORWARDED_SSL'] ?? '')) === 'on') return true;
    return false;
}

function request_base_url(): string
{
    $host = trim((string)($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''));
    if ($host === '') return AP_BASE_URL;

    if (str_contains($host, ',')) {
        $host = trim(explode(',', $host)[0]);
    }
    $host = preg_replace('/[^A-Za-z0-9\.\-:\[\]]/', '', $host) ?? '';
    if ($host === '') return AP_BASE_URL;

    $scheme = is_https_request() ? 'https' : 'http';
    return $scheme . '://' . $host;
}

function local_media_url_or_fallback(?string $url, string $fallbackPath): string
{
    $fallback = ap_url(ltrim($fallbackPath, '/'));
    $url = trim((string)$url);
    if ($url === '') return $fallback;

    $parts = parse_url($url);
    $host = strtolower((string)($parts['host'] ?? ''));
    $path = (string)($parts['path'] ?? '');
    if ($host !== '' && !is_local($host)) return $url;
    if ($path === '' || !str_starts_with($path, '/media/')) return $url;

    $file = basename($path);
    if ($file === '') return $fallback;
    $diskPath = AP_MEDIA_DIR . '/' . $file;
    return is_file($diskPath) ? $url : $fallback;
}

// ── HTTP responses ───────────────────────────────────────────

function json_out(mixed $data, int $status = 200, string $ct = 'application/json'): never
{
    if (!headers_sent()) {
        http_response_code($status);
        // JSON media types do not define a charset parameter (RFC 8259 / RFC 7033).
        // Some Mastodon iOS code paths have been sensitive to `application/json; charset=utf-8`,
        // so emit the bare media type for maximum client compatibility.
        header('Content-Type: ' . $ct);
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Expose-Headers: Link, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset');
        $rate = $GLOBALS['__rate_limit_headers'] ?? null;
        if (is_array($rate)) {
            header('X-RateLimit-Limit: ' . (int)($rate['limit'] ?? 300));
            header('X-RateLimit-Remaining: ' . max(0, (int)($rate['remaining'] ?? 0)));
            header('X-RateLimit-Reset: ' . gmdate('Y-m-d\TH:i:s.000\Z', (int)($rate['reset'] ?? time())));
        } else {
            // Mastodon-compatible fallback so clients still have self-throttling hints.
            $resetTs = (int)(ceil(time() / 300) * 300);
            header('X-RateLimit-Limit: 300');
            header('X-RateLimit-Remaining: 299');
            header('X-RateLimit-Reset: ' . gmdate('Y-m-d\TH:i:s.000\Z', $resetTs));
        }
    }
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function ap_json_out(mixed $data, int $status = 200): never
{
    json_out($data, $status, 'application/activity+json');
}

function err_out(string $msg, int $status = 400): never
{
    json_out(['error' => $msg], $status);
}

/**
 * Schedule a callable to run after the HTTP response is flushed to the client.
 * Uses fastcgi_finish_request() (LiteSpeed/PHP-FPM) to close the HTTP connection
 * while PHP continues executing — so federation deliveries do not block API latency.
 * The shutdown function runs after exit/json_out(), ensuring the response is already sent.
 */
function defer_after_response(callable $fn): void
{
    static $cbs        = [];
    static $registered = false;
    $cbs[] = $fn;
    if (!$registered) {
        $registered = true;
        register_shutdown_function(static function () use (&$cbs) {
            // Close HTTP connection to the client while PHP keeps running.
            // litespeed_finish_request() = LiteSpeed SAPI (LSAPI) equivalent of fastcgi_finish_request().
            // fastcgi_finish_request()   = PHP-FPM / FastCGI.
            // Without one of these, the fallback flushes output buffers (best-effort; may not
            // disconnect the client on all server configurations).
            if (function_exists('litespeed_finish_request')) {
                litespeed_finish_request();
            } elseif (function_exists('fastcgi_finish_request')) {
                fastcgi_finish_request();
            } else {
                ignore_user_abort(true);
                if (PHP_SAPI !== 'cli' && !headers_sent()) {
                    header('Connection: close');
                }
                while (ob_get_level()) ob_end_flush();
                flush();
            }
            foreach ($cbs as $cb) {
                try { $cb(); } catch (\Throwable) {}
            }
        });
    }
}

/**
 * Cross-request throttle for expensive background work on shared hosting.
 * Returns true when the caller may proceed now, false when it should skip.
 */
function throttle_allow(string $key, int $intervalSeconds): bool
{
    $dir = ROOT . '/storage/runtime';
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $path = $dir . '/throttle_' . md5($key) . '.lock';
    $now  = time();

    $fh = @fopen($path, 'c+');
    if (!$fh) return true;
    try {
        if (!flock($fh, LOCK_EX)) return true;
        $raw = stream_get_contents($fh);
        $last = ctype_digit(trim((string)$raw)) ? (int)trim((string)$raw) : 0;
        if ($last > 0 && ($now - $last) < $intervalSeconds) {
            flock($fh, LOCK_UN);
            fclose($fh);
            return false;
        }
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, (string)$now);
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);
        return true;
    } catch (\Throwable) {
        @fclose($fh);
        return true;
    }
}

function client_ip(): string
{
    $fwd = trim((string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
    if ($fwd !== '') {
        $first = trim(explode(',', $fwd)[0]);
        if ($first !== '') return $first;
    }
    return trim((string)($_SERVER['REMOTE_ADDR'] ?? 'unknown')) ?: 'unknown';
}

function rate_limit_bucket_path(string $scope): string
{
    $dir = ROOT . '/storage/runtime/ratelimit';
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    return $dir . '/' . md5($scope) . '.json';
}

function rate_limit_set_headers(int $limit, int $remaining, int $resetTs): void
{
    $GLOBALS['__rate_limit_headers'] = [
        'limit'     => $limit,
        'remaining' => $remaining,
        'reset'     => $resetTs,
    ];
}

function rate_limit_consume(string $scope, int $limit, int $windowSeconds): array
{
    $path = rate_limit_bucket_path($scope);
    $now  = time();
    $fh   = @fopen($path, 'c+');
    if (!$fh) {
        $reset = $now + $windowSeconds;
        rate_limit_set_headers($limit, max(0, $limit - 1), $reset);
        return ['allowed' => true, 'remaining' => max(0, $limit - 1), 'limit' => $limit, 'reset' => $reset];
    }

    try {
        if (!flock($fh, LOCK_EX)) {
            $reset = $now + $windowSeconds;
            rate_limit_set_headers($limit, max(0, $limit - 1), $reset);
            fclose($fh);
            return ['allowed' => true, 'remaining' => max(0, $limit - 1), 'limit' => $limit, 'reset' => $reset];
        }

        $raw  = stream_get_contents($fh);
        $data = json_decode($raw ?: '{}', true);
        $count = (int)($data['count'] ?? 0);
        $reset = (int)($data['reset'] ?? 0);

        if ($reset <= $now) {
            $count = 0;
            $reset = $now + $windowSeconds;
        }

        $allowed = $count < $limit;
        if ($allowed) $count++;
        $remaining = max(0, $limit - $count);

        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode(['count' => $count, 'reset' => $reset], JSON_UNESCAPED_SLASHES));
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);

        rate_limit_set_headers($limit, $remaining, $reset);
        return ['allowed' => $allowed, 'remaining' => $remaining, 'limit' => $limit, 'reset' => $reset];
    } catch (\Throwable) {
        @fclose($fh);
        $reset = $now + $windowSeconds;
        rate_limit_set_headers($limit, max(0, $limit - 1), $reset);
        return ['allowed' => true, 'remaining' => max(0, $limit - 1), 'limit' => $limit, 'reset' => $reset];
    }
}

function rate_limit_enforce(string $scope, int $limit, int $windowSeconds, string $message = 'Rate limit exceeded'): void
{
    $state = rate_limit_consume($scope, $limit, $windowSeconds);
    if (!$state['allowed']) {
        err_out($message, 429);
    }
}

// ── Request helpers ──────────────────────────────────────────

function raw_input_body(): string
{
    static $raw = null;
    if ($raw !== null) return $raw;

    if (array_key_exists('__request_local_body', $GLOBALS)) {
        $raw = (string) $GLOBALS['__request_local_body'];
        return $raw;
    }

    $raw = (string) file_get_contents('php://input');
    return $raw;
}

function req_body(): array
{
    static $parsed = null;
    if ($parsed !== null) return $parsed;

    $ct     = $_SERVER['CONTENT_TYPE'] ?? '';
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

    // multipart/form-data em PATCH: PHP não preenche $_POST nem $_FILES automaticamente
    if ($method === 'PATCH' && str_contains($ct, 'multipart/form-data')) {
        $parsed = [];
        // Extrair boundary
        $flatParts = [];
        if (preg_match('/boundary=([^\s;]+)/i', $ct, $bm)) {
            $boundary = $bm[1];
            $raw = raw_input_body();
            $parts = preg_split('/--' . preg_quote($boundary, '/') . '(?:--)?/', $raw);
            foreach ($parts as $part) {
                $part = ltrim($part, "\r\n");
                if ($part === '' || $part === '--') continue;
                [$rawHeaders, $body] = array_pad(explode("\r\n\r\n", $part, 2), 2, '');
                $body = rtrim($body, "\r\n");
                // Parse headers da part
                $headers = [];
                foreach (explode("\r\n", $rawHeaders) as $hLine) {
                    if (str_contains($hLine, ':')) {
                        [$hk, $hv] = explode(':', $hLine, 2);
                        $headers[strtolower(trim($hk))] = trim($hv);
                    }
                }
                $cd = $headers['content-disposition'] ?? '';
                // Extrair name
                if (!preg_match('/name="([^"]+)"/i', $cd, $nm)) continue;
                $name = $nm[1];
                // Ficheiro?
                if (preg_match('/filename="([^"]*)"/i', $cd, $fm)) {
                    $filename = $fm[1];
                    if ($filename !== '' && $body !== '') {
                        $tmp = tempnam(sys_get_temp_dir(), 'patch_upload_');
                        file_put_contents($tmp, $body);
                        $_FILES[$name] = [
                            'name'     => $filename,
                            'type'     => $headers['content-type'] ?? 'application/octet-stream',
                            'tmp_name' => $tmp,
                            'error'    => UPLOAD_ERR_OK,
                            'size'     => strlen($body),
                        ];
                    }
                } else {
                    $flatParts[] = rawurlencode($name) . '=' . rawurlencode($body);
                }
            }
        }
        // Use parse_str so array notation (fields_attributes[0][name]) becomes nested arrays
        parse_str(implode('&', $flatParts ?? []), $parsed);
        return $parsed;
    }

    // application/x-www-form-urlencoded em PATCH/DELETE/PUT
    // PHP não popula $_POST para DELETE/PUT, por isso é necessário parsear manualmente
    if (in_array($method, ['PATCH', 'DELETE', 'PUT']) && str_contains($ct, 'application/x-www-form-urlencoded')) {
        $raw = raw_input_body();
        parse_str($raw, $parsed);
        return $parsed;
    }

    // JSON ou POST normal
    $raw    = raw_input_body();
    $parsed = $raw !== '' ? (json_decode($raw, true) ?? []) : [];
    // Para DELETE/PUT com JSON: $_POST está vazio, usar apenas o JSON
    // Para POST normal: fazer merge de $_POST com JSON (JSON tem precedência)
    $parsed = array_merge($_POST, $parsed);
    return $parsed;
}

/**
 * Safely convert a value that may be a bool, int, or string ("true"/"false"/"1"/"0") to bool.
 * Needed because multipart/form-data and urlencoded bodies send everything as strings.
 */
function bool_val(mixed $v): bool
{
    if (is_bool($v)) return $v;
    if (is_int($v))  return $v !== 0;
    return filter_var($v, FILTER_VALIDATE_BOOLEAN);
}

function bearer(): ?string
{
    $h = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if ($h === '') {
        $h = (string)($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    }
    if ($h === '' && function_exists('getallheaders')) {
        foreach (getallheaders() as $name => $value) {
            if (strcasecmp((string)$name, 'Authorization') === 0) {
                $h = (string)$value;
                break;
            }
        }
    }
    return preg_match('/^Bearer\s+(\S+)$/i', $h, $m) ? $m[1] : null;
}

function authed_user(): ?array
{
    $ctx = auth_context();
    return $ctx['user'] ?? null;
}

function auth_context(): ?array
{
    // Accept token via Authorization header.
    // Only the SSE endpoint may use ?access_token= because EventSource cannot send headers.
    $queryToken = null;
    $path = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
    if ($path === '/api/v1/streaming/user') {
        $queryToken = $_GET['access_token'] ?? null;
    }
    $tok = bearer() ?? $queryToken ?? ($_COOKIE['ap_auth'] ?? null) ?? null;
    if (!$tok) return null;

    $row = \App\Models\OAuthModel::tokenByValue($tok);
    if (!$row || !$row['user_id']) return null;

    \App\Models\DB::update('oauth_tokens', ['last_used' => now_iso()], 'token=?', [$tok]);
    $user = \App\Models\UserModel::byId($row['user_id']);
    if (!$user || !empty($user['is_suspended'])) return null;

    return ['token' => $row, 'user' => $user];
}

function token_has_scope(string $granted, string|array|null $required): bool
{
    if ($required === null || $required === [] || $required === '') return true;
    $grantedList = preg_split('/\s+/', trim($granted)) ?: [];
    $grantedList = array_values(array_filter($grantedList, 'strlen'));
    $requiredList = is_array($required) ? $required : [$required];
    foreach ($requiredList as $scope) {
        if (in_array($scope, $grantedList, true)) return true;
    }
    return false;
}

function require_auth(string|array|null $scopes = null): array
{
    $ctx = auth_context();
    if (!$ctx) err_out('Unauthorized', 401);
    if (!token_has_scope((string)($ctx['token']['scopes'] ?? ''), $scopes)) {
        err_out('Forbidden', 403);
    }
    return $ctx['user'];
}

// ── String / content helpers ─────────────────────────────────

function uuid(): string
{
    $b = random_bytes(16);
    $b[6] = chr(ord($b[6]) & 0x0f | 0x40);
    $b[8] = chr(ord($b[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}

/**
 * Generate a Mastodon-compatible snowflake ID.
 * Format: (ms_since_epoch << 16) | sequence
 * Epoch: 2010-01-01T00:00:00Z (same as Mastodon) = 1262304000000 ms
 * IDs are monotonically increasing strings — newer post = larger ID.
 * Required by Mastodon clients (Ivory, IceCubes, etc.) for cursor-based
 * position tracking and timeline ordering.
 */
function flake_id(): string
{
    static $lastMs = 0;
    static $seq    = 0;
    static $worker = null;

    if ($worker === null) {
        $scope = (defined('ROOT') ? (string)ROOT : getcwd()) . '|' . getmypid();
        $worker = crc32($scope) & 0x3F; // 6-bit worker id, stable per process/workspace
    }

    $ms = (int)(microtime(true) * 1000);
    if ($ms === $lastMs) {
        $seq = ($seq + 1) & 0x3FF; // 10-bit per-millisecond sequence
    } else {
        $seq    = 0;
        $lastMs = $ms;
    }

    // 64-bit safe: timestamp ms + 6-bit worker + 10-bit sequence
    $id = (($ms - 1262304000000) << 16) | ($worker << 10) | $seq;
    return (string)$id;
}

function flake_id_at(?string $ts, int $seq = 0): string
{
    if (!$ts) return flake_id();
    static $worker = null;
    if ($worker === null) {
        $scope = (defined('ROOT') ? (string)ROOT : getcwd()) . '|' . getmypid();
        $worker = crc32($scope) & 0x3F;
    }
    try {
        $dt = new DateTimeImmutable($ts);
        $ms = ((int)$dt->format('U')) * 1000 + (int)$dt->format('v');
    } catch (Throwable) {
        return flake_id();
    }
    $seq = max(0, min(0x3FF, $seq));
    $id = (($ms - 1262304000000) << 16) | ($worker << 10) | $seq;
    return (string)$id;
}


// Normaliza qualquer timestamp ISO para formato UTC com milissegundos (ex: "2024-01-15T12:00:00.000Z")
// Clientes iOS (Ivory, IceCubes, Mastodon iOS) usam DateFormatter com ".SSS" obrigatório.
function iso_z(?string $ts): ?string
{
    if (!$ts) return null;
    $ts = trim($ts);

    // Fast path: already valid UTC ISO without milliseconds
    if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $ts)) {
        return substr($ts, 0, -1) . '.000Z';
    }

    // Already has milliseconds/offset? Normalize through DateTimeImmutable.
    try {
        $dt = new \DateTimeImmutable($ts);
        return $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.000\Z');
    } catch (\Throwable) {
        // Some remote software emits space-separated timestamps; strtotime handles many of them.
        $unix = strtotime($ts);
        if ($unix === false) return null;
        return gmdate('Y-m-d\TH:i:s.000\Z', $unix);
    }
}

function flake_iso(?string $id): ?string
{
    if (!is_string($id) || $id === '' || !ctype_digit($id)) return null;
    try {
        $raw = (int)$id;
        if ($raw <= 0) return null;
        $ms = ($raw >> 16) + 1262304000000;
        if ($ms <= 1262304000000) return null;
        return gmdate('Y-m-d\TH:i:s.000\Z', (int)($ms / 1000));
    } catch (\Throwable) {
        return null;
    }
}

function best_iso_timestamp(?string $primary, ?string $secondary = null, ?string $flakeId = null): string
{
    $flake = flake_iso($flakeId);
    $flakeTs = $flake !== null ? strtotime($flake) : false;

    foreach ([$primary, $secondary] as $candidate) {
        $iso = iso_z($candidate);
        if ($iso === null) continue;

        $ts = strtotime($iso);
        if ($ts !== false && $flakeTs !== false && $ts > $flakeTs + 300) {
            return $flake;
        }
        if ($ts !== false && $ts > time() + 300) {
            if ($flake !== null) return $flake;
            continue;
        }

        return $iso;
    }

    return $flake ?? now_iso();
}

function now_iso(): string
{
    return gmdate('Y-m-d\TH:i:s') . '.000Z';
}

function safe_str(string $s, int $max = 500): string
{
    return mb_substr(strip_tags($s), 0, $max);
}

/**
 * Convert HTML (e.g. from a remote AP actor summary) to clean plain text,
 * preserving paragraph and line-break structure as newlines.
 * The result can then be passed to text_to_html() for consistent rendering.
 */
function html_to_plain(string $html): string
{
    if ($html === '') return '';
    // Block-level breaks → newlines
    $text = preg_replace('~<br\s*/?>~i', "\n", $html);
    $text = preg_replace('~</p>~i', "\n\n", $text);
    $text = strip_tags($text);
    // Decode HTML entities so text_to_html() re-encodes cleanly (prevents double-encoding)
    $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    // Normalise whitespace
    $text = preg_replace('/\n{3,}/', "\n\n", trim($text));
    return $text;
}

function site_favicon_url(): string
{
    return 'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22%3E%3Ctext x=%2250%25%22 y=%2252%25%22 text-anchor=%22middle%22 dominant-baseline=%22middle%22 font-size=%2244%22 font-family=%22Arial,sans-serif%22%3E%E2%8B%B0%E2%8B%B1%3C/text%3E%3C/svg%3E';
}

function text_to_html(string $text): string
{
    if ($text === '') return '';
    $s = htmlspecialchars($text, ENT_COMPAT | ENT_HTML5, 'UTF-8');
    // mentions
    $s = preg_replace_callback(
        '/(?<![\/\w])@([A-Za-z0-9_][A-Za-z0-9_.-]*)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9.-])/u',
        static function (array $m): string {
            $username = $m[1];
            $domain   = strtolower($m[2]);
            $href     = "https://{$domain}/users/{$username}";
            if (class_exists(\App\Models\DB::class)) {
                $ra = \App\Models\DB::one('SELECT id FROM remote_actors WHERE username=? AND domain=?', [$username, $domain]);
                if ($ra && !empty($ra['id'])) $href = $ra['id'];
            }
            return '<a href="' . htmlspecialchars($href, ENT_QUOTES | ENT_HTML5, 'UTF-8')
                . '" class="u-url mention">@<span>' . htmlspecialchars($username, ENT_COMPAT | ENT_HTML5, 'UTF-8')
                . '</span></a>';
        },
        $s
    );
    // local mentions
    $s = preg_replace(
        '/(?<![\/\w])@(\w+)(?!@)(?=\s|$|[^\w])/',
        '<a href="' . AP_BASE_URL . '/users/$1" class="u-url mention">@<span>$1</span></a>',
        $s
    );
    // URLs first (must run before hashtags to prevent #fragment in URLs becoming hashtag links)
    // Limit URL match to 2048 chars to prevent regex backtracking on crafted long strings.
    $s = preg_replace(
        '~(?<!["\'])https?://[^\s<>"\')\]]{1,2048}~',
        '<a href="$0" rel="nofollow noopener noreferrer" target="_blank">$0</a>',
        $s
    );
    // hashtags — avoid matching URL fragments like #section or mid-word #tokens
    $s = preg_replace_callback(
        '/(?<![\p{L}\p{N}_\/:&?=%.\-])#([\p{L}\p{N}_]+)/u',
        static function (array $m): string {
            $tag = $m[1];
            return '<a href="' . AP_BASE_URL . '/tags/' . rawurlencode($tag) . '" class="mention hashtag" rel="tag">#<span>'
                . htmlspecialchars($tag, ENT_COMPAT | ENT_HTML5, 'UTF-8') . '</span></a>';
        },
        $s
    );
    // Split on blank lines → separate <p> elements (like Mastodon); single newline → <br>
    $paragraphs = array_values(array_filter(array_map('trim', preg_split('/\n{2,}/', $s))));
    if (!$paragraphs) return '';
    return implode('', array_map(fn($p) => '<p>' . str_replace("\n", '<br>', $p) . '</p>', $paragraphs));
}

function extract_mentions(string $text): array
{
    $out = [];
    $remoteSpans = [];
    // remote @user@domain
    if (preg_match_all('/(?<![\/\w])@([A-Za-z0-9_][A-Za-z0-9_.-]*)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9.-])/u', $text, $m, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
        foreach ($m as $r) {
            $full = $r[0][0];
            $pos  = $r[0][1];
            $remoteSpans[] = [$pos, $pos + strlen($full)];
            $out[] = ['username' => $r[1][0], 'domain' => strtolower($r[2][0]), 'remote' => true];
        }
    }
    // local @user — ignore the username portion of a remote @user@domain mention
    if (preg_match_all('/(?<![\/\w])@([A-Za-z0-9_]+)/u', $text, $m, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
        foreach ($m as $r) {
            $full = $r[0][0];
            $pos  = $r[0][1];
            $end  = $pos + strlen($full);
            $insideRemote = false;
            foreach ($remoteSpans as [$start, $stop]) {
                if ($pos >= $start && $end <= $stop) {
                    $insideRemote = true;
                    break;
                }
            }
            if ($insideRemote) continue;
            $out[] = ['username' => $r[1][0], 'domain' => AP_DOMAIN, 'remote' => false];
        }
    }
    return $out;
}

function extract_tags(string $text): array
{
    preg_match_all('/(?<![\p{L}\p{N}_\/:&?=%.\-])#([\p{L}\p{N}_]+)/u', $text, $m);
    return array_unique(array_map(static fn($t) => mb_strtolower($t, 'UTF-8'), $m[1] ?? []));
}

function get_request_headers(): array
{
    $h = [];
    foreach ($_SERVER as $k => $v) {
        if (str_starts_with($k, 'HTTP_')) {
            $h[strtolower(str_replace('_', '-', substr($k, 5)))] = $v;
        }
    }
    if (isset($_SERVER['CONTENT_TYPE']))   $h['content-type']   = $_SERVER['CONTENT_TYPE'];
    if (isset($_SERVER['CONTENT_LENGTH'])) $h['content-length'] = $_SERVER['CONTENT_LENGTH'];

    // LiteSpeed / proxies podem remover Signature e Authorization antes de chegarem ao PHP.
    // Tentar recuperá-los de locais alternativos onde o RewriteRule os pode ter preservado.
    if (empty($h['signature'])) {
        // Via getallheaders() se disponível (Apache/LiteSpeed com mod_php)
        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $val) {
                $lower = strtolower($name);
                if ($lower === 'signature' || $lower === 'authorization') {
                    $h[$lower] = $val;
                }
            }
        }
        // Via variável de ambiente definida pelo .htaccess RewriteRule
        if (empty($h['signature']) && !empty($_SERVER['HTTP_SIGNATURE'])) {
            $h['signature'] = $_SERVER['HTTP_SIGNATURE'];
        }
        if (empty($h['signature']) && !empty($_SERVER['REDIRECT_HTTP_SIGNATURE'])) {
            $h['signature'] = $_SERVER['REDIRECT_HTTP_SIGNATURE'];
        }
    }
    if (empty($h['authorization'])) {
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            $h['authorization'] = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $h['authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }
    }

    return $h;
}

/**
 * Ensure a string is safe HTML for display.
 * For remote posts that already contain HTML: strip dangerous tags but preserve structure.
 * For strings that are plain text (no tags): wrap in <p>.
 */
function ensure_html(string $content): string
{
    if ($content === '') return '';
    // If content already contains HTML tags, sanitise and return as-is
    if ($content !== strip_tags($content)) {
        $html = strip_tags($content, '<p><br><a><strong><em><code><pre><ul><ol><li><blockquote><span>');
        // Strip event handler attributes (on*) and style attributes to prevent XSS.
        // strip_tags keeps all attributes on allowed tags, so we must do this explicitly.
        $html = preg_replace('/\s+on\w+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]*)/i', '', $html);
        $html = preg_replace('/\s+style\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]*)/i', '', $html);
        // Ensure all <a> links are safe: add noopener + blank target so remote links
        // don't inherit our browsing context. Applies to all <a> tags after sanitisation.
        $html = preg_replace_callback(
            '/<a\b([^>]*)>/i',
            function ($m) {
                $attrs = $m[1];
                $safeHref = '';
                $relTokens = [];
                if (preg_match('/\shref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))/i', $attrs, $hrefMatch)) {
                    $href = html_entity_decode((string)($hrefMatch[1] ?: $hrefMatch[2] ?: $hrefMatch[3] ?: ''), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    if (preg_match('~^https?://~i', $href)) {
                        $safeHref = htmlspecialchars($href, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    }
                }
                if (preg_match('/\srel\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))/i', $attrs, $relMatch)) {
                    $relRaw = strtolower(html_entity_decode((string)($relMatch[1] ?: $relMatch[2] ?: $relMatch[3] ?: ''), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                    $relTokens = preg_split('/\s+/', trim($relRaw)) ?: [];
                }
                // Rebuild the link so unquoted or dangerous href values do not survive.
                $attrs = preg_replace('/\s+href\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]*)/i', '', $attrs);
                // Remove existing rel/target so we can re-add them canonically
                $attrs = preg_replace('/\s+(?:rel|target)\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]*)/i', '', $attrs);
                $hrefAttr = $safeHref !== '' ? ' href="' . $safeHref . '"' : '';
                $rel = in_array('me', $relTokens, true)
                    ? 'me nofollow noopener noreferrer'
                    : 'nofollow noopener noreferrer';
                return '<a' . $attrs . $hrefAttr . ' rel="' . $rel . '" target="_blank">';
            },
            $html
        );
        // Normalise apostrophe entities — some servers encode them unnecessarily,
        // and Ivory may not decode them when showing bio as plain text fallback.
        return str_replace(['&apos;', '&#039;', '&#39;'], "'", $html);
    }
    // Plain text: convert to HTML without escaping apostrophes
    $s = htmlspecialchars($content, ENT_COMPAT | ENT_HTML5, 'UTF-8');
    // Convert bare URLs to links (2048 char limit prevents regex backtracking)
    $s = preg_replace(
        '~(?<!["\'])https?://[^\s<>"\')\]]{1,2048}~',
        '<a href="$0" rel="nofollow noopener noreferrer" target="_blank">$0</a>',
        $s
    );
    // Split on blank lines → separate <p> elements; single newline → <br>
    $paragraphs = array_values(array_filter(array_map('trim', preg_split('/\n{2,}/', $s))));
    if (!$paragraphs) return '';
    return implode('', array_map(fn($p) => '<p>' . str_replace("\n", '<br>', $p) . '</p>', $paragraphs));
}

/**
 * Check if a domain is in the domain_blocks table.
 */
function is_domain_blocked(string $domain): bool
{
    try {
        return (bool)\App\Models\DB::one('SELECT 1 FROM domain_blocks WHERE domain=? COLLATE NOCASE', [$domain]);
    } catch (\Throwable) {
        return false;
    }
}
