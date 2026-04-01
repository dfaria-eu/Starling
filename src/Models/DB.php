<?php
declare(strict_types=1);

namespace App\Models;

class DB
{
    private static ?\PDO $pdo = null;

    public static function pdo(): \PDO
    {
        if (self::$pdo === null) {
            $dir = dirname(AP_DB_PATH);
            if (!is_dir($dir)) mkdir($dir, 0755, true);

            self::$pdo = new \PDO('sqlite:' . AP_DB_PATH);
            self::$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            self::$pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
            self::$pdo->exec('PRAGMA journal_mode=WAL');
            self::$pdo->exec('PRAGMA foreign_keys=ON');
            self::$pdo->exec('PRAGMA synchronous=NORMAL');
            self::$pdo->exec('PRAGMA busy_timeout=5000');  // retry up to 5s on SQLITE_BUSY instead of failing immediately
            self::$pdo->exec('PRAGMA cache_size=-10000'); // 10 MB page cache in RAM
            self::$pdo->exec('PRAGMA temp_store=MEMORY'); // temp tables in RAM, not disk
        }
        return self::$pdo;
    }

    public static function run(string $sql, array $p = []): \PDOStatement
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($p);
        return $st;
    }

    public static function one(string $sql, array $p = []): ?array
    {
        $r = self::run($sql, $p)->fetch();
        return $r === false ? null : $r;
    }

    public static function all(string $sql, array $p = []): array
    {
        return self::run($sql, $p)->fetchAll();
    }

    public static function insert(string $table, array $data): string
    {
        $cols = implode(',', array_keys($data));
        $phs  = implode(',', array_fill(0, count($data), '?'));
        self::run("INSERT INTO $table ($cols) VALUES ($phs)", array_values($data));
        return self::pdo()->lastInsertId();
    }

    public static function insertIgnore(string $table, array $data): void
    {
        $cols = implode(',', array_keys($data));
        $phs  = implode(',', array_fill(0, count($data), '?'));
        self::run("INSERT OR IGNORE INTO $table ($cols) VALUES ($phs)", array_values($data));
    }

    public static function update(string $table, array $data, string $where, array $wp = []): void
    {
        $set = implode(',', array_map(fn($k) => "$k=?", array_keys($data)));
        self::run("UPDATE $table SET $set WHERE $where", [...array_values($data), ...$wp]);
    }

    public static function delete(string $table, string $where, array $p = []): void
    {
        self::run("DELETE FROM $table WHERE $where", $p);
    }

    public static function count(string $table, string $where = '1', array $p = []): int
    {
        return (int)(self::one("SELECT COUNT(*) n FROM $table WHERE $where", $p)['n'] ?? 0);
    }
}
