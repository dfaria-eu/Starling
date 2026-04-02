<?php
declare(strict_types=1);

namespace App\ActivityPub;

class Builder
{
    private const CTX = [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1',
        [
            'manuallyApprovesFollowers' => 'as:manuallyApprovesFollowers',
            'sensitive'   => 'as:sensitive',
            'Hashtag'     => 'as:Hashtag',
            'toot'        => 'http://joinmastodon.org/ns#',
            'Emoji'       => 'toot:Emoji',
            'discoverable'=> 'toot:discoverable',
            'indexable'   => 'toot:indexable',
            'fedibird'    => 'http://fedibird.com/ns#',
            'quoteUri'    => ['@id' => 'fedibird:quoteUri', '@type' => '@id'],
        ],
    ];

    /** Expose full context for standalone object responses. */
    public static function getContext(): array
    {
        return self::CTX;
    }

    // ── Actor ────────────────────────────────────────────────

    public static function actor(array $u): array
    {
        $url = actor_url($u['username']);
        $result = [
            '@context'  => self::CTX,
            // Many servers cache and interact more reliably with bot accounts exposed as
            // Person actors. Keep the Mastodon API bot flag for clients, but use Person
            // over ActivityPub for broader federation compatibility.
            'type'      => 'Person',
            'id'        => $url,
            'following' => "$url/following",
            'followers' => "$url/followers",
            'inbox'     => "$url/inbox",
            'outbox'    => "$url/outbox",
            'featured'  => "$url/featured",
            'featuredTags' => "$url/tags",
            'endpoints' => ['sharedInbox' => ap_url('inbox')],
            'preferredUsername' => $u['username'],
            'name'      => $u['display_name'],
            'summary'   => text_to_html($u['bio'] ?? ''),
            'url'       => ap_url('@' . $u['username']),
            'published' => best_iso_timestamp($u['created_at'] ?? null, $u['updated_at'] ?? null, $u['id'] ?? null),
            'manuallyApprovesFollowers' => (bool)$u['is_locked'],
            'discoverable' => (bool)($u['discoverable'] ?? 1),
            'indexable'    => (bool)($u['indexable'] ?? 1),
            'publicKey' => [
                'id'           => "$url#main-key",
                'owner'        => $url,
                'publicKeyPem' => $u['public_key'],
            ],
            'tag'        => [],
            'attachment' => self::fieldsToAttachment($u['fields'] ?? '[]'),
        ];

        // Conditionally include optional fields — omit nulls (AP best practice)
        if ($u['avatar']) {
            $result['icon'] = ['type' => 'Image', 'mediaType' => self::mimeFromUrl($u['avatar']), 'url' => $u['avatar']];
        }
        if ($u['header']) {
            $result['image'] = ['type' => 'Image', 'mediaType' => self::mimeFromUrl($u['header']), 'url' => $u['header']];
        }
        $aka = json_decode($u['also_known_as'] ?? '[]', true) ?: [];
        if ($aka) {
            $result['alsoKnownAs'] = $aka;
        }
        if ($u['moved_to'] ?? '') {
            $result['movedTo'] = $u['moved_to'];
        }

        return $result;
    }

    // ── Note ─────────────────────────────────────────────────

    public static function note(array $s, array $u): array
    {
        $actorUrl = actor_url($u['username']);
        [$to, $cc] = self::visibility($s['visibility'], $actorUrl);
        $poll = \App\Models\PollModel::byStatusId($s['id']);

        // Build tags array
        $tags = [];
        foreach (extract_tags($s['content']) as $ht) {
            $tags[] = ['type' => 'Hashtag', 'href' => ap_url('tags/' . rawurlencode($ht)), 'name' => '#' . $ht];
        }
        foreach (extract_mentions($s['content']) as $m) {
            $href  = self::resolveActorUrl($m['username'], $m['domain'] ?? '', $m['remote'] ?? false);
            $tags[] = ['type' => 'Mention', 'href' => $href, 'name' => "@{$m['username']}" . ($m['remote'] ? "@{$m['domain']}" : '')];
            // DMs: mencionados vão para 'to'; outros: vão para 'cc'
            if ($s['visibility'] === 'direct') {
                if (!in_array($href, $to)) $to[] = $href;
            } else {
                if (!in_array($href, $to) && !in_array($href, $cc)) $cc[] = $href;
            }
        }

        $webUrl = ap_url('@' . $u['username'] . '/' . $s['id']);

        // Quote URI (FEP-e232 / fedibird extension, also used by Mastodon 4.3+)
        $quoteUri = null;
        if (!empty($s['quote_of_id'])) {
            $quoted = \App\Models\StatusModel::byId($s['quote_of_id']);
            if ($quoted && !empty($quoted['reblog_of_id'])) {
                $orig   = \App\Models\StatusModel::byId($quoted['reblog_of_id']);
                $quoted = $orig ?: $quoted;
            }
            if ($quoted && in_array($quoted['visibility'] ?? '', ['public', 'unlisted'])) {
                $quoteUri = $quoted['uri'];
            }
        }

        $noteContent = text_to_html($s['content']);
        if ($quoteUri) {
            $noteContent .= '<p>RE: <a href="' . htmlspecialchars($quoteUri, ENT_QUOTES) . '">' . htmlspecialchars($quoteUri, ENT_QUOTES) . '</a></p>';
            $tags[] = ['type' => 'Link', 'mediaType' => 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"', 'href' => $quoteUri];
        }

        $lang = $s['language'] ?? 'pt';

        $result = [
            'type'        => $poll ? 'Question' : 'Note',
            'id'          => $s['uri'],
            'attributedTo'=> $actorUrl,
            'content'     => $noteContent,
            'contentMap'  => [$lang => $noteContent],
            'published'   => best_iso_timestamp($s['created_at'] ?? null, $s['updated_at'] ?? null, $s['id'] ?? null),
            'url'         => $webUrl,
            'to'          => $to,
            'cc'          => array_values(array_unique($cc)),
            'sensitive'   => (bool)$s['sensitive'],
            'tag'         => $tags,
            'attachment'  => self::buildAttachments($s['id']),
            'replies'     => $poll ? null : [
                'type'       => 'Collection',
                'id'         => $s['uri'] . '/replies',
                'first'      => [
                    'type'  => 'CollectionPage',
                    'partOf'=> $s['uri'] . '/replies',
                    'items' => [],
                ],
            ],
        ];

        // Conditionally include optional fields — omit nulls
        if ($s['updated_at'] && $s['updated_at'] !== $s['created_at']) {
            $result['updated'] = best_iso_timestamp($s['updated_at'] ?? null, $s['created_at'] ?? null, $s['id'] ?? null);
        }
        if ($s['cw'] ?? '') {
            $result['summary'] = $s['cw'];
        }
        if ($s['reply_to_id'] ?? null) {
            $result['inReplyTo'] = self::replyToUri($s['reply_to_id']);
        }
        if ($quoteUri) {
            $result['quoteUri'] = $quoteUri;
        }
        if ($poll) {
            $result = array_merge($result, \App\Models\PollModel::toActivityPub($poll));
            unset($result['replies']);
        }

        return $result;
    }

    // ── Activity wrappers ─────────────────────────────────────

    public static function create(array $s, array $u): array
    {
        $note    = self::note($s, $u);
        $actorUrl = actor_url($u['username']);
        return [
            '@context'  => self::CTX,
            'type'      => 'Create',
            'id'        => $s['uri'] . '#create',
            'actor'     => $actorUrl,
            'published' => best_iso_timestamp($s['created_at'] ?? null, $s['updated_at'] ?? null, $s['id'] ?? null),
            'to'        => $note['to'],
            'cc'        => $note['cc'],
            'object'    => $note,
        ];
    }

    public static function update(array $s, array $u): array
    {
        $note     = self::note($s, $u);
        $actorUrl = actor_url($u['username']);
        return [
            '@context'  => self::CTX,
            'type'      => 'Update',
            'id'        => $s['uri'] . '#update/' . md5($s['updated_at']),
            'actor'     => $actorUrl,
            'published' => best_iso_timestamp($s['updated_at'] ?? null, $s['created_at'] ?? null, $s['id'] ?? null),
            'to'        => $note['to'],
            'cc'        => $note['cc'],
            'object'    => $note,
        ];
    }

    public static function vote(array $status, array $poll, array $user, string $choiceTitle): array
    {
        $actorUrl = actor_url($user['username']);
        $choiceTitle = trim($choiceTitle);
        return [
            '@context'  => self::CTX,
            'type'      => 'Create',
            'id'        => $actorUrl . '#votes/' . md5($status['uri'] . '|' . $choiceTitle . '|' . microtime(true)),
            'actor'     => $actorUrl,
            'to'        => [$status['user_id']],
            'object'    => [
                'id'           => $actorUrl . '#vote-note/' . md5($status['uri'] . '|' . $choiceTitle . '|' . microtime(true)),
                'type'         => 'Note',
                'attributedTo' => $actorUrl,
                'inReplyTo'    => $status['uri'],
                'name'         => $choiceTitle,
                'to'           => [$status['user_id']],
                'published'    => now_iso(),
            ],
        ];
    }

    public static function delete(string $objectUri, array $u, ?array $s = null): array
    {
        $actorUrl = actor_url($u['username']);
        $to = ['https://www.w3.org/ns/activitystreams#Public'];
        $cc = [];
        if ($s) {
            [$to, $cc] = self::visibility($s['visibility'] ?? 'public', $actorUrl);
            foreach (extract_mentions($s['content'] ?? '') as $m) {
                $href = self::resolveActorUrl($m['username'], $m['domain'] ?? '', $m['remote'] ?? false);
                if (($s['visibility'] ?? 'public') === 'direct') {
                    if (!in_array($href, $to, true)) $to[] = $href;
                } else {
                    if (!in_array($href, $to, true) && !in_array($href, $cc, true)) $cc[] = $href;
                }
            }
        }
        return [
            '@context' => self::CTX,
            'type'     => 'Delete',
            'id'       => $objectUri . '#delete',
            'actor'    => $actorUrl,
            'to'       => array_values(array_unique($to)),
            'cc'       => array_values(array_unique($cc)),
            'object'   => ['type' => 'Tombstone', 'id' => $objectUri],
        ];
    }

    public static function follow(array $follower, string $targetUrl): array
    {
        $fUrl = actor_url($follower['username']);
        return [
            '@context' => self::CTX,
            'type'     => 'Follow',
            'id'       => $fUrl . '#follow/' . md5($targetUrl),
            'actor'    => $fUrl,
            'to'       => [$targetUrl],
            'object'   => $targetUrl,
        ];
    }

    public static function undoFollow(array $follower, string $targetUrl): array
    {
        $fUrl  = actor_url($follower['username']);
        $inner = self::follow($follower, $targetUrl);
        unset($inner['@context']);
        return [
            '@context' => self::CTX,
            'type'     => 'Undo',
            'id'       => $fUrl . '#undo-follow/' . md5($targetUrl),
            'actor'    => $fUrl,
            'to'       => [$targetUrl],
            'object'   => $inner,
        ];
    }

    public static function block(array $actor, string $targetUrl): array
    {
        $actorUrl = actor_url($actor['username']);
        return [
            '@context' => self::CTX,
            'type'     => 'Block',
            'id'       => $actorUrl . '#block/' . md5($targetUrl),
            'actor'    => $actorUrl,
            'to'       => [$targetUrl],
            'object'   => $targetUrl,
        ];
    }

    public static function undoBlock(array $actor, string $targetUrl): array
    {
        $actorUrl = actor_url($actor['username']);
        $inner    = self::block($actor, $targetUrl);
        unset($inner['@context']);
        return [
            '@context' => self::CTX,
            'type'     => 'Undo',
            'id'       => $actorUrl . '#undo-block/' . md5($targetUrl),
            'actor'    => $actorUrl,
            'to'       => [$targetUrl],
            'object'   => $inner,
        ];
    }

    public static function accept(array $actor, array $followActivity): array
    {
        $followId = is_string($followActivity['id'] ?? null) ? $followActivity['id'] : json_encode($followActivity);
        $to       = is_string($followActivity['actor'] ?? null) ? [$followActivity['actor']] : [];
        return [
            '@context' => self::CTX,
            'type'     => 'Accept',
            'id'       => actor_url($actor['username']) . '#accept/' . md5($followId),
            'actor'    => actor_url($actor['username']),
            'to'       => $to,
            'object'   => $followActivity,
        ];
    }

    public static function reject(array $actor, array $followActivity): array
    {
        $followId = is_string($followActivity['id'] ?? null) ? $followActivity['id'] : json_encode($followActivity);
        $to       = is_string($followActivity['actor'] ?? null) ? [$followActivity['actor']] : [];
        return [
            '@context' => self::CTX,
            'type'     => 'Reject',
            'id'       => actor_url($actor['username']) . '#reject/' . md5($followId),
            'actor'    => actor_url($actor['username']),
            'to'       => $to,
            'object'   => $followActivity,
        ];
    }

    public static function announce(array $boost, array $target, array $u): array
    {
        $actorUrl = actor_url($u['username']);
        [$to, $cc] = self::visibility((string)($target['visibility'] ?? 'public'), $actorUrl);
        return [
            '@context' => self::CTX,
            'type'     => 'Announce',
            'id'       => $actorUrl . '#announce/' . $boost['id'],
            'actor'    => $actorUrl,
            'published'=> best_iso_timestamp($boost['created_at'] ?? null, null, $boost['id'] ?? null),
            'to'       => $to,
            'cc'       => $cc,
            'object'   => $target['uri'],
        ];
    }

    public static function undoAnnounce(array $boost, array $target, array $u): array
    {
        $actorUrl = actor_url($u['username']);
        $inner    = self::announce($boost, $target, $u);
        unset($inner['@context']);
        return [
            '@context' => self::CTX,
            'type'     => 'Undo',
            'id'       => $actorUrl . '#undo-announce/' . $boost['id'],
            'actor'    => $actorUrl,
            'to'       => $inner['to'] ?? [],
            'cc'       => $inner['cc'] ?? [],
            'object'   => $inner,
        ];
    }

    public static function like(array $s, array $u): array
    {
        $targetActor = str_starts_with((string)$s['user_id'], 'http')
            ? (string)$s['user_id']
            : (($owner = \App\Models\UserModel::byId((string)$s['user_id'])) ? actor_url($owner['username']) : (string)$s['user_id']);
        return [
            '@context' => self::CTX,
            'type'     => 'Like',
            'id'       => actor_url($u['username']) . '#like/' . $s['id'],
            'actor'    => actor_url($u['username']),
            'to'       => [$targetActor],
            'object'   => $s['uri'],
        ];
    }

    public static function undoLike(array $s, array $u): array
    {
        $inner = self::like($s, $u);
        unset($inner['@context']);
        return [
            '@context' => self::CTX,
            'type'     => 'Undo',
            'id'       => actor_url($u['username']) . '#undo-like/' . $s['id'],
            'actor'    => actor_url($u['username']),
            'to'       => $inner['to'],
            'object'   => $inner,
        ];
    }

    public static function move(array $actor, string $newActorUrl): array
    {
        $actorUrl = actor_url($actor['username']);
        return [
            '@context' => self::CTX,
            'type'     => 'Move',
            'id'       => $actorUrl . '#move/' . md5($newActorUrl),
            'actor'    => $actorUrl,
            'to'       => ['https://www.w3.org/ns/activitystreams#Public'],
            'cc'       => ["$actorUrl/followers", $newActorUrl],
            'object'   => $actorUrl,
            'target'   => $newActorUrl,
        ];
    }

    public static function updateActor(array $u): array
    {
        $actorUrl = actor_url($u['username']);
        $actorObj = self::actor($u);
        unset($actorObj['@context']);
        return [
            '@context' => self::CTX,
            'type'     => 'Update',
            'id'       => $actorUrl . '#update-actor/' . md5($u['updated_at']),
            'actor'    => $actorUrl,
            'to'       => ['https://www.w3.org/ns/activitystreams#Public'],
            'object'   => $actorObj,
        ];
    }

    // ── Collection helpers ───────────────────────────────────

    public static function collection(string $id, int $total): array
    {
        return [
            '@context'   => 'https://www.w3.org/ns/activitystreams',
            'type'       => 'OrderedCollection',
            'id'         => $id,
            'totalItems' => $total,
            'first'      => $id . '?page=1',
        ];
    }

    public static function collectionPage(string $id, int $page, array $items, int $total, int $limit = 20): array
    {
        $out = [
            '@context'     => 'https://www.w3.org/ns/activitystreams',
            'type'         => 'OrderedCollectionPage',
            'id'           => $id . '?page=' . $page,
            'partOf'       => $id,
            'totalItems'   => $total,
            'orderedItems' => $items,
        ];
        if (($page * $limit) < $total) $out['next'] = $id . '?page=' . ($page + 1);
        if ($page > 1)               $out['prev'] = $id . '?page=' . ($page - 1);
        return $out;
    }

    // ── Private helpers ──────────────────────────────────────

    private static function mimeFromUrl(string $url): string
    {
        $ext = strtolower(pathinfo(parse_url($url, PHP_URL_PATH) ?? '', PATHINFO_EXTENSION));
        return match ($ext) {
            'png'  => 'image/png',
            'gif'  => 'image/gif',
            'webp' => 'image/webp',
            'avif' => 'image/avif',
            'heic' => 'image/heic',
            'heif' => 'image/heif',
            'svg'  => 'image/svg+xml',
            default => 'image/jpeg',
        };
    }

    private static function fieldsToAttachment(string $json): array
    {
        $fields = json_decode($json, true);
        if (!is_array($fields)) return [];
        return array_values(array_filter(array_map(fn($f) => !empty($f['name']) ? [
            'type'  => 'PropertyValue',
            'name'  => $f['name'],
            'value' => \App\Models\UserModel::fieldValueToHtml($f['value'] ?? ''),
        ] : null, $fields)));
    }

    // Resolve a URL AP de um actor a partir de username+domain
    private static function resolveActorUrl(string $username, string $domain, bool $remote): string
    {
        if (!$remote || !$domain) return actor_url($username);
        $ra = \App\Models\DB::one('SELECT id FROM remote_actors WHERE username=? AND domain=?', [$username, $domain]);
        if (!$ra) {
            $ra = \App\Models\RemoteActorModel::fetchByAcct($username, $domain);
        }
        return $ra ? $ra['id'] : "https://{$domain}/users/{$username}";
    }

    // Resolve o URI do post pai para inReplyTo
    private static function replyToUri(string $replyToId): string
    {
        if (str_starts_with($replyToId, 'http')) return $replyToId;
        $s = \App\Models\StatusModel::byId($replyToId);
        return $s ? $s['uri'] : ap_url('objects/' . $replyToId);
    }

    private static function visibility(string $vis, string $actorUrl): array
    {
        $pub = 'https://www.w3.org/ns/activitystreams#Public';
        return match ($vis) {
            'public'   => [[$pub], ["$actorUrl/followers"]],
            'unlisted' => [["$actorUrl/followers"], [$pub]],
            'private'  => [["$actorUrl/followers"], []],
            'direct'   => [[], []],
            default    => [[$pub], ["$actorUrl/followers"]],
        };
    }

    private static function buildAttachments(string $statusId): array
    {
        $rows = \App\Models\DB::all(
            'SELECT ma.* FROM media_attachments ma JOIN status_media sm ON sm.media_id=ma.id WHERE sm.status_id=? ORDER BY sm.position',
            [$statusId]
        );
        return array_map(function($m) {
            $ext  = strtolower(pathinfo(parse_url($m['url'], PHP_URL_PATH) ?? '', PATHINFO_EXTENSION));
            $mime = match($ext) {
                'jpg', 'jpeg' => 'image/jpeg',
                'png'         => 'image/png',
                'gif'         => 'image/gif',
                'webp'        => 'image/webp',
                'avif'        => 'image/avif',
                'heic'        => 'image/heic',
                'heif'        => 'image/heif',
                'svg'         => 'image/svg+xml',
                'mp4'         => 'video/mp4',
                'webm'        => 'video/webm',
                'mov'         => 'video/quicktime',
                'mp3'         => 'audio/mpeg',
                'ogg'         => 'audio/ogg',
                'wav'         => 'audio/wav',
                default       => str_starts_with($m['type'], 'video') ? 'video/mp4' : 'image/jpeg',
            };
            $att = [
                'type'      => 'Document',
                'mediaType' => $mime,
                'url'       => $m['url'],
            ];
            if ($m['description'] ?? '') $att['name'] = $m['description'];
            if ($m['blurhash'] ?? '')    $att['blurhash'] = $m['blurhash'];
            if ($m['width'] ?? null)     $att['width'] = (int)$m['width'];
            if ($m['height'] ?? null)    $att['height'] = (int)$m['height'];
            return $att;
        }, $rows);
    }
}
