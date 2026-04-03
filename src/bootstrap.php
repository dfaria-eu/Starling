<?php
declare(strict_types=1);

// ── Autoloader ──────────────────────────────────────────────
spl_autoload_register(function (string $class): void {
    if (strncmp('App\\', $class, 4) !== 0) return;

    $rel  = substr($class, 4);
    $file = ROOT . '/src/' . str_replace('\\', '/', $rel) . '.php';
    if (is_file($file)) { require_once $file; return; }

    // MiscCtrl.php and ExtrasCtrl.php each contain multiple classes without dedicated files.
    // Load them lazily: try each file and stop as soon as the needed class is defined.
    if (str_starts_with($rel, 'Controllers\\Api\\')) {
        foreach (['MiscCtrl', 'ExtrasCtrl'] as $mf) {
            $path = ROOT . '/src/Controllers/Api/' . $mf . '.php';
            if (is_file($path)) require_once $path;
            if (class_exists('App\\' . $rel, false)) break;
        }
    }
});

// ── Helpers ─────────────────────────────────────────────────
require ROOT . '/src/helpers.php';

// ── Auto-create DB schema ────────────────────────────────────
\App\Models\Schema::install();

$writeGeneratedConfig = static function (array $config): bool {
    $path = ROOT . '/storage/config.generated.php';
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        return false;
    }
    $php = "<?php\nreturn " . var_export($config, true) . ";\n";
    return @file_put_contents($path, $php, LOCK_EX) !== false;
};

$migrateLegacyConfig = static function (int $userCount) use ($writeGeneratedConfig): void {
    $generatedPath = ROOT . '/storage/config.generated.php';
    if (is_file($generatedPath)) {
        return;
    }

    // Only migrate established installs. Fresh installs should keep using the
    // installer/config flow until the first admin account exists.
    if ($userCount <= 0) {
        return;
    }

    $legacyConfig = [
        'installed'     => true,
        'domain'        => AP_DOMAIN,
        'name'          => AP_NAME,
        'description'   => AP_DESCRIPTION,
        'admin_email'   => AP_ADMIN_EMAIL,
        'base_url'      => AP_BASE_URL,
        'db_path'       => AP_DB_PATH,
        'media_dir'     => AP_MEDIA_DIR,
        'max_upload_mb' => AP_MAX_UPLOAD_MB,
        'open_reg'      => AP_OPEN_REG,
        'post_chars'    => AP_POST_CHARS,
        'debug'         => AP_DEBUG,
        'version'       => AP_VERSION,
        'software'      => AP_SOFTWARE,
        'source_url'    => defined('AP_SOURCE_URL') ? AP_SOURCE_URL : AP_BASE_URL,
        'atproto_did'   => defined('AP_ATPROTO_DID') ? AP_ATPROTO_DID : '',
    ];

    if (!$writeGeneratedConfig($legacyConfig)) {
        error_log('Could not auto-migrate legacy config.php values to storage/config.generated.php');
    }
};

$userCount = \App\Models\DB::count('users');
$migrateLegacyConfig($userCount);

$apAllowInstall = defined('AP_ALLOW_INSTALL') ? (bool)AP_ALLOW_INSTALL : false;
if ($apAllowInstall && $userCount === 0) {
    $requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
    if ($requestPath !== '/install' && $requestPath !== '/install/' && !str_starts_with($requestPath, '/api/')) {
        header('Location: /install', true, 302);
        exit;
    }
}

// ── Security headers ─────────────────────────────────────────
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; img-src 'self' data: https:; media-src 'self' data: https: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; font-src 'self' data:; frame-ancestors 'self';");
    if (!AP_DEBUG && is_https_request()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

// ── Opportunistic async work ────────────────────────────────
// Shared hosting often has no cron/queue worker. Drain a small slice of the
// federation retry queue after ordinary requests so deliveries keep flowing.
// Skip long-lived streaming endpoints to avoid holding an SSE connection open.
$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
if (!str_starts_with($requestPath, '/api/v1/streaming')) {
    defer_after_response(static function (): void {
        if (throttle_allow('delivery_retry_queue', 30)) {
            \App\ActivityPub\Delivery::processRetryQueue(\App\ActivityPub\Delivery::requestDrainBatch());
        }
        if (throttle_allow('local_status_expiry', 60)) {
            \App\Models\StatusModel::deleteExpiredLocal(25);
        }
        \App\Models\AdminModel::runAutoMaintenanceIfDue();
    });
}


// ── Error handling ───────────────────────────────────────────
if (!AP_DEBUG) {
    set_error_handler(function (int $errno, string $msg, string $file, int $line): bool {
        error_log("[$errno] $msg in $file:$line");
        return true;
    });
    set_exception_handler(function (\Throwable $e): void {
        error_log($e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
        if (!headers_sent()) {
            json_out(['error' => 'Internal server error'], 500);
        }
        echo json_encode(['error' => 'Internal server error']);
        exit;
    });
}
