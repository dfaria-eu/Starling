<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Models\DB;
use App\ActivityPub\Builder;
class TagCtrl {
    public function show(array $p): void {
        $tag = mb_strtolower((string)$p['tag'], 'UTF-8');
        $url   = ap_url('tags/' . rawurlencode($tag));
        $page  = max(1, (int)($_GET['page'] ?? 1));
        $rows  = DB::all(
            "SELECT s.uri FROM statuses s
             JOIN status_hashtags sh ON sh.status_id=s.id
             JOIN hashtags h ON h.id=sh.hashtag_id
             WHERE h.name=? AND s.visibility='public'
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
               AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))
             ORDER BY s.created_at DESC
             LIMIT 20 OFFSET ?",
            [$tag, now_iso(), ($page - 1) * 20]
        );
        $total = (int)(DB::one(
            "SELECT COUNT(*) c FROM statuses s
             JOIN status_hashtags sh ON sh.status_id=s.id
             JOIN hashtags h ON h.id=sh.hashtag_id
             WHERE h.name=? AND s.visibility='public'
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
               AND (s.user_id LIKE 'http%' OR s.user_id NOT IN (SELECT id FROM users WHERE is_suspended=1))",
            [$tag, now_iso()]
        )['c'] ?? 0);

        if (!isset($_GET['page'])) {
            ap_json_out(Builder::collection($url, $total));
        }

        ap_json_out(Builder::collectionPage($url, $page, array_column($rows, 'uri'), $total));
    }
}
