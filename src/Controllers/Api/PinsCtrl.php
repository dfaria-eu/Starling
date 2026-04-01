<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, StatusModel};

class PinsCtrl
{
    public function pin(array $p): void
    {
        $user = require_auth('write');
        $s    = StatusModel::byId($p['id']);
        if (!$s) err_out('Not found', 404);
        if ($s['user_id'] !== $user['id']) err_out('Forbidden', 403);
        if ($s['reblog_of_id']) err_out('Cannot pin a boost', 422);
        if (!in_array($s['visibility'], ['public', 'unlisted'])) err_out('Cannot pin a non-public post', 422);

        $alreadyPinned = (bool)DB::one('SELECT 1 FROM status_pins WHERE user_id=? AND status_id=?', [$user['id'], $s['id']]);
        if ($alreadyPinned) {
            json_out(StatusModel::toMasto(StatusModel::byId($s['id']), $user['id']));
        }

        $count = DB::count('status_pins', 'user_id=?', [$user['id']]);
        if ($count >= 20) err_out('Maximum number of pinned statuses reached', 422);

        DB::insertIgnore('status_pins', [
            'id'         => uuid(),
            'user_id'    => $user['id'],
            'status_id'  => $s['id'],
            'created_at' => now_iso(),
        ]);

        json_out(StatusModel::toMasto(StatusModel::byId($s['id']), $user['id']));
    }

    public function unpin(array $p): void
    {
        $user = require_auth('write');
        $s    = StatusModel::byId($p['id']);
        if (!$s) err_out('Not found', 404);
        DB::delete('status_pins', 'user_id=? AND status_id=?', [$user['id'], $s['id']]);
        json_out(StatusModel::toMasto(StatusModel::byId($s['id']), $user['id']));
    }
}
