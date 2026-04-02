<?php
declare(strict_types=1);

namespace App\Models;

class PollModel
{
    public static function closeExpiredPolls(int $limit = 25): int
    {
        $limit = max(1, min($limit, 500));
        $rows = DB::all(
            'SELECT id, expires_at
             FROM polls
             WHERE closed_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?
             ORDER BY expires_at ASC
             LIMIT ?',
            [gmdate('Y-m-d\TH:i:s\Z'), $limit]
        );
        if (!$rows) return 0;

        $closed = 0;
        foreach ($rows as $poll) {
            $expiresTs = strtotime((string)($poll['expires_at'] ?? ''));
            if (!$expiresTs) continue;
            $ts = gmdate('Y-m-d\TH:i:s\Z', $expiresTs);
            DB::update('polls', ['closed_at' => $ts, 'updated_at' => now_iso()], 'id=? AND closed_at IS NULL', [$poll['id']]);
            $closed++;
        }
        return $closed;
    }

    public static function byId(string $id): ?array
    {
        $poll = DB::one(
            'SELECT p.*, s.local, s.user_id, s.visibility, s.uri
             FROM polls p
             JOIN statuses s ON s.id = p.status_id
             WHERE p.id=?',
            [$id]
        );
        if ($poll) self::closeIfExpired($poll);
        return $poll;
    }

    public static function byStatusId(string $statusId): ?array
    {
        $poll = DB::one(
            'SELECT p.*, s.local, s.user_id, s.visibility, s.uri
             FROM polls p
             JOIN statuses s ON s.id = p.status_id
             WHERE p.status_id=?',
            [$statusId]
        );
        if ($poll) self::closeIfExpired($poll);
        return $poll;
    }

    public static function createForStatus(string $statusId, array $pollData): ?array
    {
        $options = array_values(array_filter(array_map(
            fn($v) => trim((string)$v),
            (array)($pollData['options'] ?? [])
        ), fn(string $v) => $v !== ''));

        if (count($options) < 2 || count($options) > 4) {
            err_out('Poll must have between 2 and 4 options', 422);
        }
        foreach ($options as $opt) {
            if (mb_strlen($opt) > 50) err_out('Poll option too long', 422);
        }

        $expiresIn = (int)($pollData['expires_in'] ?? 0);
        if ($expiresIn < 300 || $expiresIn > 2629746) {
            err_out('Invalid poll expiration', 422);
        }

        $multiple   = bool_val($pollData['multiple'] ?? false);
        $hideTotals = bool_val($pollData['hide_totals'] ?? false);
        $now        = now_iso();
        $pollId     = uuid();

        DB::insert('polls', [
            'id'          => $pollId,
            'status_id'   => $statusId,
            'multiple'    => (int)$multiple,
            'hide_totals' => (int)$hideTotals,
            'expires_at'  => gmdate('Y-m-d\TH:i:s\Z', time() + $expiresIn),
            'closed_at'   => null,
            'votes_count' => 0,
            'voters_count'=> 0,
            'created_at'  => $now,
            'updated_at'  => $now,
        ]);

        foreach ($options as $pos => $title) {
            DB::insert('poll_options', [
                'id'         => uuid(),
                'poll_id'    => $pollId,
                'title'      => $title,
                'position'   => $pos,
                'votes_count'=> 0,
            ]);
        }

        return self::byId($pollId);
    }

    public static function syncRemoteQuestion(string $statusId, array $obj): void
    {
        $multiple = isset($obj['anyOf']);
        $choices  = self::extractQuestionOptions($obj);
        if (count($choices) < 2) return;

        $poll = self::byStatusId($statusId);
        $now  = now_iso();
        $expiresAt = self::apTimestampString($obj['endTime'] ?? null);
        $closedAt  = self::apTimestampString($obj['closed'] ?? null);
        $existingPoll = $poll;
        $totalVotes = 0;
        $voters = is_numeric($obj['votersCount'] ?? null) ? (int)$obj['votersCount'] : null;

        if (!$poll) {
            DB::insert('polls', [
                'id'          => uuid(),
                'status_id'   => $statusId,
                'multiple'    => (int)$multiple,
                'hide_totals' => 0,
                'expires_at'  => $expiresAt,
                'closed_at'   => $closedAt,
                'votes_count' => 0,
                'voters_count'=> 0,
                'created_at'  => $now,
                'updated_at'  => $now,
            ]);
            $poll = self::byStatusId($statusId);
            if (!$poll) return;
        } else {
            DB::update('polls', [
                'multiple'    => (int)$multiple,
                'expires_at'  => $expiresAt,
                'closed_at'   => $closedAt,
                'updated_at'  => $now,
            ], 'id=?', [$poll['id']]);
        }

        $existingOptions = self::options($poll['id']);
        $byPosition = [];
        $byNormTitle = [];
        foreach ($existingOptions as $opt) {
            $byPosition[(string)$opt['position']] = $opt;
            $byNormTitle[mb_strtolower(trim((string)$opt['title']))] = $opt;
        }

        $seenOptionIds = [];
        foreach ($choices as $pos => $choice) {
            $incomingVotes = max(0, (int)($choice['votes_count'] ?? 0));
            $normTitle = mb_strtolower(trim((string)$choice['title']));
            $existing = $byPosition[(string)$pos] ?? $byNormTitle[$normTitle] ?? null;
            if ($existing) {
                $votes = $incomingVotes;
                $seenOptionIds[] = $existing['id'];
                DB::update('poll_options', [
                    'title'       => $choice['title'],
                    'position'    => $pos,
                    'votes_count' => $votes,
                ], 'id=?', [$existing['id']]);
            } else {
                $votes = $incomingVotes;
                $newId = uuid();
                $seenOptionIds[] = $newId;
                DB::insert('poll_options', [
                    'id'         => $newId,
                    'poll_id'    => $poll['id'],
                    'title'      => $choice['title'],
                    'position'   => $pos,
                    'votes_count'=> $votes,
                ]);
            }
            $totalVotes += $votes;
        }

        foreach ($existingOptions as $opt) {
            if (!in_array($opt['id'], $seenOptionIds, true)) {
                DB::delete('poll_votes', 'option_id=?', [$opt['id']]);
                DB::delete('poll_options', 'id=?', [$opt['id']]);
            }
        }
        $finalVotes = $totalVotes;
        $finalVoters = $voters !== null
            ? max(0, $voters)
            : ((bool)$multiple ? max(0, (int)($existingPoll['voters_count'] ?? 0)) : $totalVotes);

        DB::update('polls', [
            'votes_count'  => $finalVotes,
            'voters_count' => $finalVoters,
            'updated_at'   => $now,
        ], 'id=?', [$poll['id']]);
    }

    public static function syncRemoteMastoPoll(string $statusId, array $pollData): void
    {
        $choices = [];
        foreach ((array)($pollData['options'] ?? []) as $opt) {
            if (!is_array($opt)) continue;
            $title = trim((string)($opt['title'] ?? ''));
            if ($title === '') continue;
            $choices[] = [
                'type'    => 'Note',
                'name'    => $title,
                'replies' => ['type' => 'Collection', 'totalItems' => max(0, (int)($opt['votes_count'] ?? 0))],
            ];
        }
        if (count($choices) < 2) return;

        $obj = [
            'type'        => (bool)($pollData['multiple'] ?? false) ? 'Question' : 'Question',
            (bool)($pollData['multiple'] ?? false) ? 'anyOf' : 'oneOf' => $choices,
            'votersCount' => max(0, (int)($pollData['voters_count'] ?? $pollData['votes_count'] ?? 0)),
            'endTime'     => $pollData['expires_at'] ?? null,
            'closed'      => !empty($pollData['expired']) ? ($pollData['expires_at'] ?? now_iso()) : null,
        ];

        self::syncRemoteQuestion($statusId, $obj);
    }

    private static function voteOrThrow(array $poll, string $userId, array $choices, bool $incrementTotals = true): array
    {
        self::closeIfExpired($poll);
        if (!empty($poll['closed_at'])) {
            throw new \RuntimeException('Poll has already ended');
        }
        if (DB::one('SELECT 1 FROM poll_votes WHERE poll_id=? AND user_id=?', [$poll['id'], $userId])) {
            throw new \RuntimeException('Already voted');
        }

        $options = self::options($poll['id']);
        if (!$options) {
            throw new \RuntimeException('Poll not found');
        }
        $byPos = [];
        foreach ($options as $opt) $byPos[(string)$opt['position']] = $opt;

        $choices = array_values(array_unique(array_map(fn($v) => (string)$v, $choices)));
        if (!$choices) {
            throw new \RuntimeException('choices required');
        }
        if (!(bool)$poll['multiple'] && count($choices) !== 1) {
            throw new \RuntimeException('Single-choice poll');
        }
        if ((bool)$poll['multiple'] && count($choices) > count($options)) {
            throw new \RuntimeException('Too many choices');
        }

        $pdo = DB::pdo();
        $pdo->beginTransaction();
        try {
            foreach ($choices as $choice) {
                $opt = $byPos[$choice] ?? null;
                if (!$opt) throw new \RuntimeException('Invalid choice');
                DB::insert('poll_votes', [
                    'id'         => uuid(),
                    'poll_id'    => $poll['id'],
                    'option_id'  => $opt['id'],
                    'user_id'    => $userId,
                    'created_at' => now_iso(),
                ]);
                if ($incrementTotals) {
                    DB::run('UPDATE poll_options SET votes_count=votes_count+1 WHERE id=?', [$opt['id']]);
                }
            }
            if ($incrementTotals) {
                DB::run(
                    'UPDATE polls
                     SET votes_count=votes_count+?, voters_count=voters_count+1, updated_at=?
                     WHERE id=?',
                    [count($choices), now_iso(), $poll['id']]
                );
            } else {
                DB::run('UPDATE polls SET updated_at=? WHERE id=?', [now_iso(), $poll['id']]);
            }
            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw ($e instanceof \RuntimeException ? $e : new \RuntimeException('Unable to vote', 0, $e));
        }

        return self::byId($poll['id']) ?? $poll;
    }

    public static function vote(array $poll, string $userId, array $choices, bool $incrementTotals = true): array
    {
        try {
            return self::voteOrThrow($poll, $userId, $choices, $incrementTotals);
        } catch (\RuntimeException $e) {
            $status = $e->getMessage() === 'Poll not found' ? 404 : 422;
            err_out($e->getMessage(), $status);
        }
    }

    public static function tryVote(array $poll, string $userId, array $choices, bool $incrementTotals = true): ?array
    {
        try {
            return self::voteOrThrow($poll, $userId, $choices, $incrementTotals);
        } catch (\RuntimeException) {
            return null;
        }
    }

    public static function toMasto(array $poll, ?string $viewerId = null): array
    {
        self::closeIfExpired($poll);
        $poll = self::byId($poll['id']) ?? $poll;
        if ((int)($poll['local'] ?? 0) === 0 && (int)($poll['votes_count'] ?? 0) === 0 && (int)($poll['voters_count'] ?? 0) === 0) {
            self::refreshRemoteTalliesIfPossible($poll);
            $poll = self::byId($poll['id']) ?? $poll;
        }
        $options = self::options($poll['id']);
        $ownVotes = $viewerId ? array_map('intval', array_column(
            DB::all(
                'SELECT po.position
                 FROM poll_votes pv
                 JOIN poll_options po ON po.id = pv.option_id
                 WHERE pv.poll_id=? AND pv.user_id=?
                 ORDER BY po.position ASC',
                [$poll['id'], $viewerId]
            ),
            'position'
        )) : [];
        $voted = $viewerId ? !empty($ownVotes) : false;
        $expired = !empty($poll['closed_at']) || (!empty($poll['expires_at']) && strtotime((string)$poll['expires_at']) <= time());
        $showTotals = !$poll['hide_totals'] || $expired || $voted;

        return [
            'id'           => $poll['id'],
            'expires_at'   => iso_z($poll['expires_at']) ?? null,
            'expired'      => $expired,
            'multiple'     => (bool)$poll['multiple'],
            'votes_count'  => (int)$poll['votes_count'],
            'voters_count' => (int)$poll['voters_count'],
            'options'      => array_map(fn(array $opt) => [
                'title'       => $opt['title'],
                'votes_count' => $showTotals ? (int)$opt['votes_count'] : null,
            ], $options),
            'emojis'       => [],
            'voted'        => $voted,
            'own_votes'    => $ownVotes,
            'hide_totals'  => (bool)$poll['hide_totals'],
        ];
    }

    public static function options(string $pollId): array
    {
        return DB::all('SELECT * FROM poll_options WHERE poll_id=? ORDER BY position ASC', [$pollId]);
    }

    public static function choiceTitles(array $poll, array $positions): array
    {
        $out = [];
        $byPos = [];
        foreach (self::options($poll['id']) as $opt) $byPos[(string)$opt['position']] = $opt['title'];
        foreach ($positions as $pos) {
            $title = $byPos[(string)$pos] ?? null;
            if ($title !== null) $out[] = $title;
        }
        return $out;
    }

    public static function choicePositionsByTitles(array $poll, array $titles): array
    {
        $norm = static fn(string $s): string => mb_strtolower(trim($s));
        $map = [];
        foreach (self::options($poll['id']) as $opt) $map[$norm($opt['title'])] = (int)$opt['position'];
        $out = [];
        foreach ($titles as $title) {
            $key = $norm((string)$title);
            if ($key !== '' && array_key_exists($key, $map)) $out[] = $map[$key];
        }
        return array_values(array_unique($out));
    }

    public static function deleteByStatus(string $statusId): void
    {
        $poll = DB::one('SELECT id FROM polls WHERE status_id=?', [$statusId]);
        if (!$poll) return;
        DB::delete('poll_votes', 'poll_id=?', [$poll['id']]);
        DB::delete('poll_options', 'poll_id=?', [$poll['id']]);
        DB::delete('polls', 'id=?', [$poll['id']]);
    }

    public static function toActivityPub(array $poll): array
    {
        $options = self::options($poll['id']);
        $field   = (bool)$poll['multiple'] ? 'anyOf' : 'oneOf';
        $items = array_map(static fn(array $opt) => [
            'type'    => 'Note',
            'name'    => $opt['title'],
            'replies' => ['type' => 'Collection', 'totalItems' => (int)$opt['votes_count']],
        ], $options);

        $out = [
            'votersCount' => (int)$poll['voters_count'],
            $field        => $items,
        ];
        if (!empty($poll['expires_at'])) $out['endTime'] = $poll['expires_at'];
        if (!empty($poll['closed_at'])) $out['closed'] = $poll['closed_at'];
        return $out;
    }

    private static function extractQuestionOptions(array $obj): array
    {
        $raw = [];
        foreach ((array)($obj['oneOf'] ?? []) as $choice) $raw[] = $choice;
        foreach ((array)($obj['anyOf'] ?? []) as $choice) $raw[] = $choice;

        $out = [];
        foreach ($raw as $choice) {
            if (!is_array($choice)) continue;
            $title = trim((string)($choice['name'] ?? ''));
            if ($title === '') continue;
            $votes = 0;
            if (is_array($choice['replies'] ?? null)) {
                $votes = max(0, (int)($choice['replies']['totalItems'] ?? 0));
            }
            $out[] = ['title' => $title, 'votes_count' => $votes];
        }
        return $out;
    }

    private static function apTimestampString(mixed $value): ?string
    {
        if (!is_string($value) || $value === '') return null;
        $ts = strtotime($value);
        return $ts ? gmdate('Y-m-d\TH:i:s\Z', $ts) : null;
    }

    private static function closeIfExpired(array &$poll): void
    {
        if (!empty($poll['closed_at']) || empty($poll['expires_at'])) return;
        $expiresTs = strtotime((string)$poll['expires_at']);
        if ($expiresTs && $expiresTs <= time()) {
            $closed = gmdate('Y-m-d\TH:i:s\Z', $expiresTs);
            DB::update('polls', ['closed_at' => $closed, 'updated_at' => now_iso()], 'id=? AND closed_at IS NULL', [$poll['id']]);
            $poll['closed_at'] = $closed;
            $poll['updated_at'] = now_iso();
        }
    }

    private static function refreshRemoteTalliesIfPossible(array $poll): void
    {
        $uri = (string)($poll['uri'] ?? '');
        if ($uri === '') return;
        if (!throttle_allow('remote_poll_refresh:' . $poll['id'], 5)) return;

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
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
        if (!is_string($raw) || $raw === '') return;

        $data = json_decode($raw, true);
        if (!is_array($data) || !is_array($data['poll'] ?? null)) return;
        self::syncRemoteMastoPoll($poll['status_id'], $data['poll']);
    }
}
