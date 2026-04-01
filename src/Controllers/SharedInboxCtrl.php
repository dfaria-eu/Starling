<?php
declare(strict_types=1);
namespace App\Controllers;
use App\ActivityPub\InboxProcessor;
class SharedInboxCtrl {
    public function handle(array $p): void {
        $raw = raw_input_body();
        if (!$raw) err_out('Empty body', 400);
        $activity = json_decode($raw, true);
        if (!is_array($activity)) err_out('Invalid JSON', 400);
        $actorUrl = is_string($activity['actor'] ?? null) ? $activity['actor'] : ($activity['actor']['id'] ?? '');
        $actorHost = parse_url($actorUrl, PHP_URL_HOST) ?: 'unknown';
        rate_limit_enforce('shared_inbox_ip:' . client_ip(), 120, 300, 'Rate limit exceeded for inbox');
        rate_limit_enforce('shared_inbox_actor:' . $actorHost, 120, 300, 'Rate limit exceeded for inbox');
        InboxProcessor::process($activity, get_request_headers(), 'POST', '/inbox', $raw);
        // Process the retry queue after the 202 is sent — the remote server
        // gets an immediate response and we deliver in the background.
        defer_after_response(static function (): void {
            if (throttle_allow('delivery_retry_queue', 10)) {
                \App\ActivityPub\Delivery::processRetryQueue(10);
            }
        });
        json_out(['status' => 'accepted'], 202);
    }
}
