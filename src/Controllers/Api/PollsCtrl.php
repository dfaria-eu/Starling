<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{PollModel, StatusModel, UserModel, RemoteActorModel};
use App\ActivityPub\{Builder, Delivery};
use App\ActivityPub\InboxProcessor;

class PollsCtrl
{
    public function show(array $p): void
    {
        $viewer = authed_user();
        $poll = PollModel::byId($p['id']);
        if (!$poll) err_out('Not found', 404);

        $status = StatusModel::byId($poll['status_id']);
        if (!$status || !StatusModel::canView($status, $viewer['id'] ?? null)) err_out('Not found', 404);

        json_out(PollModel::toMasto($poll, $viewer['id'] ?? null));
    }

    public function vote(array $p): void
    {
        $user = require_auth('write');
        $poll = PollModel::byId($p['id']);
        if (!$poll) err_out('Not found', 404);

        $status = StatusModel::byId($poll['status_id']);
        if (!$status || !StatusModel::canView($status, $user['id'])) err_out('Not found', 404);

        $d = req_body();
        $choices = array_values((array)($d['choices'] ?? []));
        $poll = PollModel::vote($poll, $user['id'], $choices, (int)($poll['local'] ?? 0) === 1);

        if ((int)($poll['local'] ?? 0) === 1) {
            $owner = UserModel::byId($status['user_id']);
            if ($owner) {
                $update = Builder::update($status, $owner);
                Delivery::queueToFollowers($owner, $update);
            }
        } else {
            $remote = RemoteActorModel::fetch($status['user_id']) ?? RemoteActorModel::fetch((string)$status['user_id'], true);
            if ($remote) {
                $delivered = false;
                foreach (PollModel::choiceTitles($poll, $choices) as $title) {
                    $activity = Builder::vote($status, $poll, $user, $title);
                    if (!$delivered) {
                        $delivered = Delivery::toActor($user, $remote, $activity);
                    }
                    if (!$delivered) {
                        Delivery::queueToActor($user, $remote, $activity);
                    }
                }
                if ($delivered && !empty($status['uri'])) {
                    // Refresh the remote Question right after a successful direct vote.
                    // Some servers accept the vote first and publish the updated Question a
                    // few hundred milliseconds later, so retry briefly before returning.
                    $uri = (string)$status['uri'];
                    for ($i = 0; $i < 4; $i++) {
                        InboxProcessor::fetchRemoteNote($uri, false, 0, true);
                        $fresh = PollModel::byId($poll['id']) ?? $poll;
                        $hasTallies = (int)($fresh['votes_count'] ?? 0) > 0 || (int)($fresh['voters_count'] ?? 0) > 0;
                        if ($hasTallies) {
                            $poll = $fresh;
                            break;
                        }
                        if ($i < 3) usleep(300000);
                        $poll = $fresh;
                    }
                    if ((int)($poll['votes_count'] ?? 0) === 0 && (int)($poll['voters_count'] ?? 0) === 0) {
                        $this->refreshRemotePollViaMastoApi($status, $poll);
                    }
                }
            }
        }

        json_out(PollModel::toMasto($poll, $user['id']));
    }

    private function refreshRemotePollViaMastoApi(array $status, array &$poll): void
    {
        $uri = (string)($status['uri'] ?? '');
        if ($uri === '') return;
        $parts = parse_url($uri);
        $host = (string)($parts['host'] ?? '');
        $path = trim((string)($parts['path'] ?? ''), '/');
        $segments = $path === '' ? [] : explode('/', $path);
        $remoteId = end($segments);
        if ($host === '' || !ctype_digit((string)$remoteId)) return;

        $endpoint = 'https://' . $host . '/api/v1/statuses/' . rawurlencode((string)$remoteId);
        if (!RemoteActorModel::isSafeUrl($endpoint)) return;

        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => [
                'Accept: application/json',
                'User-Agent: ' . AP_SOFTWARE . '/' . AP_VERSION . ' (+https://' . AP_DOMAIN . ')',
            ],
        ]);
        $raw = curl_exec($ch);
        curl_close($ch);
        if (!is_string($raw) || $raw === '') return;

        $data = json_decode($raw, true);
        if (!is_array($data) || !is_array($data['poll'] ?? null)) return;

        PollModel::syncRemoteMastoPoll($status['id'], $data['poll']);
        $poll = PollModel::byId($poll['id']) ?? $poll;
    }
}
