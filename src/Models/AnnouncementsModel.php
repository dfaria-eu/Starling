<?php
declare(strict_types=1);

namespace App\Models;

class AnnouncementsModel
{
    private static function path(): string
    {
        return ROOT . '/storage/runtime/announcements.json';
    }

    /** @return array<int,array<string,mixed>> */
    private static function load(): array
    {
        $path = self::path();
        if (!is_file($path)) return [];
        $data = json_decode((string)@file_get_contents($path), true);
        if (!is_array($data)) return [];
        return array_values(array_filter($data, 'is_array'));
    }

    private static function renderContent(array $row): string
    {
        $title = trim((string)($row['title'] ?? ''));
        $text  = trim((string)($row['text'] ?? ''));
        $out   = '';
        if ($title !== '') {
            $out .= '<p><strong>' . htmlspecialchars($title, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</strong></p>';
        }
        if ($text !== '') {
            $out .= '<p>' . nl2br(htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8')) . '</p>';
        }
        return $out;
    }

    private static function isVisible(array $row, string $now): bool
    {
        if (array_key_exists('active', $row) && empty($row['active'])) return false;
        $startsAt = trim((string)($row['starts_at'] ?? ''));
        $endsAt   = trim((string)($row['ends_at'] ?? ''));
        if ($startsAt !== '' && $startsAt > $now) return false;
        if ($endsAt !== '' && $endsAt < $now) return false;
        return true;
    }

    /** @return array<int,array<string,mixed>> */
    public static function visible(): array
    {
        $now  = gmdate('Y-m-d\TH:i:s\Z');
        $rows = array_values(array_filter(self::load(), static fn(array $row): bool => self::isVisible($row, $now)));
        usort($rows, static fn(array $a, array $b): int => strcmp((string)($b['published_at'] ?? ''), (string)($a['published_at'] ?? '')));

        return array_map(static function (array $row): array {
            $publishedAt = trim((string)($row['published_at'] ?? '')) ?: now_iso();
            $updatedAt   = trim((string)($row['updated_at'] ?? '')) ?: $publishedAt;
            return [
                'id'           => (string)($row['id'] ?? md5(json_encode($row))),
                'content'      => self::renderContent($row),
                'starts_at'    => trim((string)($row['starts_at'] ?? '')) ?: null,
                'ends_at'      => trim((string)($row['ends_at'] ?? '')) ?: null,
                'published_at' => $publishedAt,
                'updated_at'   => $updatedAt,
                'all_day'      => false,
                'published'    => true,
                'read'         => false,
                'mentions'     => [],
                'statuses'     => [],
                'tags'         => [],
                'emojis'       => [],
                'reactions'    => [],
            ];
        }, $rows);
    }
}
