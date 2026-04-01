<?php
declare(strict_types=1);

// Detect ROOT automatically.
$candidates = [
    __DIR__,                           // Everything in the public root (flat layout)
    dirname(__DIR__),                  // Separate public/ directory
    dirname(__DIR__, 2) . '/activitypub-php',
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
    echo "\nPlace config/, src/, and storage/ in the same directory as this index.php.\n";
    exit;
}

define('ROOT', $root);
require ROOT . '/config/config.php';
require ROOT . '/src/bootstrap.php';
(new \App\Router())->dispatch();
