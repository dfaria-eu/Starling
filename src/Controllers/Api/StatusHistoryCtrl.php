<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, StatusModel, PollModel};

class StatusHistoryCtrl
{
    /**
     * GET /api/v1/statuses/:id/history
     * Returns edit history ordered from newest to oldest.
     */
    public function history(array $p): void
    {
        $viewer = authed_user();
        $s      = StatusModel::byId($p['id']);
        if (!$s || !StatusModel::canView($s, $viewer['id'] ?? null)) err_out('Not found', 404);

        $accountObj = UserModel::byId($s['user_id']);
        if ($accountObj) {
            $accountOut = UserModel::toMasto($accountObj, $viewer['id'] ?? null);
        } else {
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$s['user_id']]);
            if (!$ra) err_out('Not found', 404);
            $accountOut = UserModel::remoteToMasto($ra);
        }

        $media = DB::all(
            'SELECT ma.* FROM media_attachments ma JOIN status_media sm ON sm.media_id=ma.id WHERE sm.status_id=? ORDER BY sm.position',
            [$s['id']]
        );
        $poll = PollModel::byStatusId($s['id']);

        $fmt = fn(array $row, bool $isCurrent) => [
            'created_at'      => best_iso_timestamp($row['created_at'] ?? null, $s['updated_at'] ?? $s['created_at'] ?? null, null),
            'content'         => (int)($s['local'] ?? 1) ? text_to_html($row['content']) : ensure_html($row['content']),
            'spoiler_text'    => $row['cw'],
            'sensitive'       => (bool)$row['sensitive'],
            'account'         => $accountOut,
            // We only persist textual edit snapshots. Returning current media/poll for
            // older revisions makes history lie after attachment or poll changes.
            'media_attachments'=> $isCurrent ? array_map([\App\Models\MediaModel::class, 'toMasto'], $media) : [],
            'emojis'          => [],
            'poll'            => $isCurrent && $poll ? PollModel::toMasto($poll, $viewer['id'] ?? null) : null,
        ];

        $history = [[
            'content'    => $s['content'],
            'cw'         => $s['cw'],
            'sensitive'  => $s['sensitive'],
            'created_at' => $s['updated_at'] ?: $s['created_at'],
        ]];
        foreach (DB::all('SELECT * FROM status_edits WHERE status_id=? ORDER BY created_at DESC', [$s['id']]) as $edit) {
            $history[] = $edit;
        }

        json_out(array_map(function(array $row, int $idx) use ($fmt, $s) {
            $out = $fmt($row, $idx === 0);
            $out['created_at'] = best_iso_timestamp($row['created_at'] ?? null, $s['updated_at'] ?? $s['created_at'] ?? null, null);
            return $out;
        }, $history, array_keys($history)));
    }

    /**
     * GET /api/v1/statuses/:id/source
     * Returns the raw text before HTML conversion (needed for edit prefill).
     */
    public function source(array $p): void
    {
        $user = require_auth('read');
        $s    = StatusModel::byId($p['id']);
        if (!$s) err_out('Not found', 404);
        if ($s['user_id'] !== $user['id']) err_out('Forbidden', 403);
        $media = DB::all(
            'SELECT ma.* FROM media_attachments ma JOIN status_media sm ON sm.media_id=ma.id WHERE sm.status_id=? ORDER BY sm.position',
            [$s['id']]
        );
        $plainText = (string)($s['content'] ?? '');
        $richSource = (bool)($s['local'] ?? 1) && local_markup_uses_rich_formatting($plainText);

        json_out([
            'id'           => $s['id'],
            'text'         => $richSource ? text_to_html($plainText) : $plainText,
            'text_plain'   => $plainText,
            'content_type' => $richSource ? 'text/html' : 'text/plain',
            'spoiler_text' => $s['cw'],
            'visibility'   => $s['visibility'] ?? 'public',
            'expires_at'   => iso_z($s['expires_at'] ?? null),
            'media_ids'    => array_column($media, 'id'),
            'media_attachments' => array_map([\App\Models\MediaModel::class, 'toMasto'], $media),
            'poll'         => (($poll = PollModel::byStatusId($s['id'])) ? [
                'options'     => array_map(fn(array $o) => $o['title'], PollModel::options($poll['id'])),
                'expires_at'  => iso_z($poll['expires_at']) ?? null,
                'multiple'    => (bool)$poll['multiple'],
                'hide_totals' => (bool)$poll['hide_totals'],
            ] : null),
        ]);
    }
}
