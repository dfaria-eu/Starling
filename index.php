<?php
declare(strict_types=1);

// Detectar ROOT automaticamente
$candidates = [
    __DIR__,                          // tudo na raiz pública (estrutura flat)
    dirname(__DIR__),                  // public/ separado (estrutura projectada)
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
    echo "ERRO: config/config.php não encontrado.\n\n";
    echo "Locais procurados:\n";
    foreach ($candidates as $c) echo "  $c/config/config.php\n";
    echo "\nColoca este index.php no document root e, sempre que possivel, mantem config/, src/ e storage/ fora da pasta publica.\n";
    echo "Se o shared host obrigar uma estrutura flat, garante que esses diretorios ficam bloqueados no servidor web.\n";
    exit;
}

define('ROOT', $root);
require ROOT . '/config/config.php';
require ROOT . '/src/bootstrap.php';
(new \App\Router())->dispatch();
