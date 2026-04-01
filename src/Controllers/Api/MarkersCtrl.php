<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\DB;

class MarkersCtrl
{
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
                $out->$tl = [
                    'last_read_id' => $row['last_read_id'],
                    'version'      => (int)$row['version'],
                    'updated_at'   => iso_z($row['updated_at']),
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
                'SELECT version FROM markers WHERE user_id=? AND timeline=?',
                [$user['id'], $tl]
            );
            // Mastodon clients can send stale marker versions from multiple tabs/devices.
            // Rejecting those with 409 causes noisy failures during perfectly valid
            // read-position updates, so accept the latest write and bump the version.
            $version = $existing ? (int)$existing['version'] + 1 : 1;

            if ($existing) {
                DB::update('markers', [
                    'last_read_id' => $lastReadId,
                    'version'      => $version,
                    'updated_at'   => $now,
                ], 'user_id=? AND timeline=?', [$user['id'], $tl]);
            } else {
                DB::insertIgnore('markers', [
                    'id'           => uuid(),
                    'user_id'      => $user['id'],
                    'timeline'     => $tl,
                    'last_read_id' => $lastReadId,
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
                    [$now, $user['id'], $lastReadId]
                );
            }

            $out->$tl = [
                'last_read_id' => $lastReadId,
                'version'      => $version,
                'updated_at'   => iso_z($now),
            ];
        }
        json_out($out);
    }
}
