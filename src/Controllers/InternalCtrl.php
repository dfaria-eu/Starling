<?php
declare(strict_types=1);

namespace App\Controllers;

class InternalCtrl
{
    public function queueWake(array $p): void
    {
        $provided = trim((string)($_SERVER['HTTP_X_QUEUE_WAKE'] ?? ''));
        $expected = \App\ActivityPub\Delivery::wakeSecret();
        if ($provided === '' || $expected === '' || !hash_equals($expected, $provided)) {
            err_out('Not Found', 404);
        }

        \App\ActivityPub\Delivery::processRetryQueue(50);

        if (\App\ActivityPub\Delivery::hasDueRetries()) {
            defer_after_response(static function (): void {
                \App\ActivityPub\Delivery::nudgeQueue(true);
            });
        }

        json_out(['status' => 'ok']);
    }
}
