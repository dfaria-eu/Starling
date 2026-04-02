<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Models\{DB, UserModel, StatusModel};
use App\ActivityPub\Builder;
class NoteCtrl {
    public function show(array $p): void {
        $s = StatusModel::byId($p['id']);
        if (!$s) {
            // Check if this was a deleted post — return 410 Gone with Tombstone
            $uri = ap_url('objects/' . $p['id']);
            $tomb = DB::one('SELECT deleted_at FROM tombstones WHERE uri=?', [$uri]);
            if ($tomb) {
                ap_json_out([
                    '@context' => 'https://www.w3.org/ns/activitystreams',
                    'type'     => 'Tombstone',
                    'id'       => $uri,
                    'deleted'  => $tomb['deleted_at'],
                ], 410);
            }
            err_out('Not found', 404);
        }
        // Only serve public and unlisted posts — private/direct posts must not be
        // accessible without authentication and are not federatable via this endpoint.
        if (!in_array($s['visibility'], ['public', 'unlisted'])) err_out('Not found', 404);
        if (!StatusModel::canView($s, null)) err_out('Not found', 404);
        $u = UserModel::byId($s['user_id']);
        if ($u && !empty($u['is_suspended'])) $u = null;
        if (!$u) err_out('Not found', 404);
        $note = Builder::note($s, $u);
        $note = ['@context' => Builder::getContext()] + $note;
        ap_json_out($note);
    }
}
