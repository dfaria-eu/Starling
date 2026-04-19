<?php
declare(strict_types=1);
namespace App\Controllers;
use App\ActivityPub\InboxProcessor;
class SharedInboxCtrl {
    public function handle(array $p): void {
        $maxBody = 2 * 1024 * 1024;
        $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($contentLength > $maxBody) err_out('Payload too large', 413);
        $raw = raw_input_body();
        if (!$raw) err_out('Empty body', 400);
        if (strlen($raw) > $maxBody) err_out('Payload too large', 413);
        $activity = json_decode($raw, true);
        if (!is_array($activity)) err_out('Invalid JSON', 400);
        $actorUrl = is_string($activity['actor'] ?? null) ? $activity['actor'] : ($activity['actor']['id'] ?? '');
        $actorHost = parse_url($actorUrl, PHP_URL_HOST) ?: 'unknown';
        rate_limit_enforce('shared_inbox_ip:' . client_ip(), 120, 300, 'Rate limit exceeded for inbox');
        rate_limit_enforce('shared_inbox_actor:' . $actorHost, 120, 300, 'Rate limit exceeded for inbox');
        $path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '/inbox', PHP_URL_PATH);
        $query = (string)parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_QUERY);
        if ($query !== '') $path .= '?' . $query;
        InboxProcessor::process($activity, get_request_headers(), 'POST', $path ?: '/inbox', $raw);
        // Process the retry queue after the 202 is sent — the remote server
        // gets an immediate response and we deliver in the background.
        defer_after_response(static function (): void {
            if (throttle_allow('delivery_retry_queue', 10)) {
                \App\ActivityPub\Delivery::processRetryQueue(\App\ActivityPub\Delivery::inboxDrainBatch());
            }
        });
        json_out(['status' => 'accepted'], 202);
    }
}
