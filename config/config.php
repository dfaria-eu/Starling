<?php
declare(strict_types=1);

$starlingDefaults = [
    'installed'     => false,
    'domain'        => 'example.com',
    'name'          => 'Starling',
    'description'   => 'A lightweight ActivityPub server.',
    'admin_email'   => 'admin@example.com',
    'base_url'      => 'https://example.com',
    'db_path'       => ROOT . '/storage/db/activitypub.sqlite',
    'media_dir'     => ROOT . '/storage/media',
    'max_upload_mb' => 8,
    'open_reg'      => false,
    'post_chars'    => 5000,
    'debug'         => false,
    'version'       => '0.0.3',
    'software'      => 'starling',
    'source_url'    => 'https://github.com/dfaria-eu/Starling/',
    'atproto_did'   => '',
];

$starlingConfigFile = ROOT . '/storage/config.generated.php';
$starlingLoaded = [];
if (is_file($starlingConfigFile)) {
    $starlingLoaded = require $starlingConfigFile;
    if (!is_array($starlingLoaded)) {
        $starlingLoaded = [];
    }
}

$starlingCfg = array_merge($starlingDefaults, $starlingLoaded);
$starlingBaseUrl = rtrim((string)($starlingCfg['base_url'] ?? ''), '/');
if ($starlingBaseUrl === '') {
    $starlingBaseUrl = 'https://' . $starlingCfg['domain'];
}
$starlingDomain = (string)parse_url($starlingBaseUrl, PHP_URL_HOST);
if ($starlingDomain === '') {
    $starlingDomain = (string)$starlingCfg['domain'];
}
$starlingDescription = trim((string)($starlingCfg['description'] ?? ''));
if ($starlingDescription === '') {
    $starlingDescription = (string)$starlingCfg['name'] . ' is an ActivityPub server.';
}
$starlingSourceUrl = trim((string)($starlingCfg['source_url'] ?? ''));
if ($starlingSourceUrl === '') {
    $starlingSourceUrl = $starlingBaseUrl;
}

define('AP_ALLOW_INSTALL', empty($starlingCfg['installed']));
define('AP_DOMAIN',        $starlingDomain);
define('AP_NAME',          (string)$starlingCfg['name']);
define('AP_DESCRIPTION',   $starlingDescription);
define('AP_ADMIN_EMAIL',   (string)$starlingCfg['admin_email']);
define('AP_BASE_URL',      $starlingBaseUrl);

// ROOT is defined automatically by index.php
define('AP_DB_PATH',       (string)$starlingCfg['db_path']);
define('AP_MEDIA_DIR',     (string)$starlingCfg['media_dir']);
define('AP_MEDIA_URL',     AP_BASE_URL . '/media');
define('AP_MAX_UPLOAD_MB', (int)$starlingCfg['max_upload_mb']);

define('AP_OPEN_REG',      (bool)$starlingCfg['open_reg']);  // false = only admins can create accounts
define('AP_POST_CHARS',    (int)$starlingCfg['post_chars']);
define('AP_DEBUG',         (bool)$starlingCfg['debug']);
define('AP_VERSION',       (string)$starlingCfg['version']);
define('AP_SOFTWARE',      (string)$starlingCfg['software']);

define('AP_SOURCE_URL',    $starlingSourceUrl);
define('AP_ATPROTO_DID',   (string)$starlingCfg['atproto_did']);
