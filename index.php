<?php
declare(strict_types=1);

// Detect the project root from common deployment layouts.
$candidates = [
    __DIR__,          // Flat layout: index.php sits beside config/, src/, storage/
    dirname(__DIR__), // Split layout: index.php sits inside a dedicated public/ dir
];

$root = null;
foreach ($candidates as $c) {
    if (is_file($c . '/config/config.php')) {
        $root = $c;
        break;
    }
}

if ($root === null) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "ERROR: config/config.php not found.\n\n";
    echo "Checked locations:\n";
    foreach ($candidates as $c) echo "  $c/config/config.php\n";
    echo "\nPlace the Starling project root where this index.php can find config/config.php.\n";
    echo "Supported layouts include a flat install or a separate public web root.\n";
    exit;
}

define('ROOT', $root);
require ROOT . '/config/config.php';
require ROOT . '/src/bootstrap.php';
(new \App\Router())->dispatch();
