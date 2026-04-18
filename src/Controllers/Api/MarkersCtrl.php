<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\DB;

class MarkersCtrl
{
    private function maxMarkerId(string $current, string $incoming): string
    {
        if ($current === '') return $incoming;
        if ($incoming === '') return $current;
        if (ctype_digit($current) && ctype_digit($incoming)) {
            $lenCmp = strlen($current) <=> strlen($incoming);
            if ($lenCmp !== 0) return $lenCmp > 0 ? $current : $incoming;
            return strcmp($current, $incoming) >= 0 ? $current : $incoming;
        }
        return strcmp($current, $incoming) >= 0 ? $current : $incoming;
    }

    /**
     * GET /api/v1/markers?timeline[]=home&timeline[]=notifications
     */
    public function show(array $p): void
    {
        $user = require_auth('read');

        // Accept both timeline[]=home and timeline[home]=1 formats
        $timelines = $_GET['timeline'] ?? [];
        if (!is_array($timelines)) $timelines = [$timelines];
        if ($timelines) {
            $keys = array_keys($timelines);
            $isAssoc = $keys !== range(0, count($timelines) - 1);
            if ($isAssoc) {
                $timelines = array_keys(array_filter($timelines, fn($v) => bool_val($v)));
            }
        }

        $out = new \stdClass();
        foreach ($timelines as $tl) {
            if (!in_array($tl, ['home', 'notifications'], true)) continue;
            $row = DB::one(
                'SELECT * FROM markers WHERE user_id=? AND timeline=?',
                [$user['id'], $tl]
            );
            if ($row) {
                $payload = [
                    'last_read_id' => $row['last_read_id'],
                    'version'      => (int)$row['version'],
                    'updated_at'   => iso_z($row['updated_at']),
                ];
                if ($tl === 'notifications') {
                    $payload['unread_count'] = DB::count('notifications', 'user_id=? AND read_at IS NULL', [$user['id']]);
                }
                $out->$tl = $payload;
            } elseif ($tl === 'notifications') {
                $out->$tl = [
                    'last_read_id' => '0',
                    'version'      => 0,
                    'updated_at'   => null,
                    'unread_count' => DB::count('notifications', 'user_id=? AND read_at IS NULL', [$user['id']]),
                ];
            }
        }
        json_out($out);
    }

    /**
     * POST /api/v1/markers
     * Body: {"home":{"last_read_id":"..."}, "notifications":{"last_read_id":"..."}}
     */
    public function update(array $p): void
    {
        $user = require_auth('write');
        $d    = req_body();
        $now  = now_iso();
        $out  = new \stdClass();

        foreach (['home', 'notifications'] as $tl) {
            if (!isset($d[$tl])) continue;
            $lastReadId = (string)($d[$tl]['last_read_id'] ?? '');
            if (!$lastReadId) continue;
            $existing = DB::one(
                'SELECT last_read_id, version FROM markers WHERE user_id=? AND timeline=?',
                [$user['id'], $tl]
            );
            // Mastodon clients can send stale marker versions from multiple tabs/devices.
            // Rejecting those with 409 causes noisy failures during perfectly valid
            // read-position updates. Accept the write, but never let the marker move
            // backwards when an older tab/device submits a stale last_read_id.
            $effectiveLastReadId = $existing
                ? $this->maxMarkerId((string)($existing['last_read_id'] ?? ''), $lastReadId)
                : $lastReadId;
            $version = $existing ? (int)$existing['version'] + 1 : 1;

            if ($existing) {
                DB::update('markers', [
                    'last_read_id' => $effectiveLastReadId,
                    'version'      => $version,
                    'updated_at'   => $now,
                ], 'user_id=? AND timeline=?', [$user['id'], $tl]);
            } else {
                DB::insertIgnore('markers', [
                    'id'           => uuid(),
                    'user_id'      => $user['id'],
                    'timeline'     => $tl,
                    'last_read_id' => $effectiveLastReadId,
                    'version'      => $version,
                    'updated_at'   => $now,
                ]);
            }

            if ($tl === 'notifications') {
                // Keep per-notification read_at reasonably aligned with the higher-level
                // marker so Mastodon-compatible clients that look at individual rows
                // do not keep treating the whole list as unread.
                DB::run(
                    'UPDATE notifications
                     SET read_at=COALESCE(read_at, ?)
                     WHERE user_id=? AND read_at IS NULL AND CAST(id AS INTEGER) <= CAST(? AS INTEGER)',
                    [$now, $user['id'], $effectiveLastReadId]
                );
            }

            $out->$tl = [
                'last_read_id' => $effectiveLastReadId,
                'version'      => $version,
                'updated_at'   => iso_z($now),
            ];
            if ($tl === 'notifications') {
                $out->$tl['unread_count'] = DB::count('notifications', 'user_id=? AND read_at IS NULL', [$user['id']]);
            }
        }
        json_out($out);
    }
}
