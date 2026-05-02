<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Models\{DB, UserModel, StatusModel, PollModel};
use App\ActivityPub\{Builder, InboxProcessor};

class ActorCtrl
{
    public function index(array $p): void
    {
        header('Content-Type: text/html; charset=utf-8');

        $users = DB::all(
            "SELECT username, display_name, bio, avatar, header, follower_count, status_count, created_at
             FROM users
             WHERE is_suspended=0
             ORDER BY follower_count DESC, status_count DESC, created_at ASC
             LIMIT 50"
        );
        $loginCta = '<a href="/web/login" class="public-nav-action">Log in</a>';
        $registerCta = AP_OPEN_REG ? '<a href="/web/register" class="public-nav-action public-nav-action-primary">Create account</a>' : '';
        $rows = '';
        foreach ($users as $u) {
            $name = htmlspecialchars((string)($u['display_name'] ?: $u['username']), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $handle = htmlspecialchars('@' . $u['username'] . '@' . AP_DOMAIN, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $url = htmlspecialchars(ap_url('@' . $u['username']), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $avatar = htmlspecialchars(local_media_url_or_fallback($u['avatar'] ?? '', '/img/avatar.svg'), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $bioSource = trim((string)($u['bio'] ?? ''));
            $bio = htmlspecialchars(function_exists('mb_substr') ? mb_substr($bioSource, 0, 180) : substr($bioSource, 0, 180), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $followers = (int)($u['follower_count'] ?? 0);
            $statuses = (int)($u['status_count'] ?? 0);
            $rows .= <<<HTML
<a class="members-card" href="$url">
  <img class="members-avatar" src="$avatar" alt="">
  <div class="members-body">
    <div class="members-name">$name</div>
    <div class="members-handle">$handle</div>
    <div class="members-bio">{$bio}</div>
    <div class="members-meta"><span>{$followers} followers</span><span>{$statuses} posts</span></div>
  </div>
</a>
HTML;
        }

        $empty = $rows === '' ? '<div class="members-empty">No local profiles yet.</div>' : $rows;
        $title = htmlspecialchars(AP_NAME . ' members', ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $favicon = htmlspecialchars(\site_favicon_url(), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        echo <<<HTML
<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title</title>
<link rel="icon" href="$favicon">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#fff;--surface:#fff;--hover:#F3F3F8;--blue:#0085FF;--blue2:#0070E0;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--text3:#8D99A5}
@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--hover:#1E2030;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--text3:#545864}}
body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{color:inherit;text-decoration:none}
.public-nav{max-width:760px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.85rem 1rem;border-bottom:1px solid var(--border);background:color-mix(in srgb,var(--surface) 85%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);position:sticky;top:0;z-index:12}
.public-nav-brand{display:flex;align-items:center;gap:.5rem;font-weight:800;color:var(--blue)}
.public-nav-brand-symbol{font-size:1.4rem;line-height:1}
.public-nav-actions{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}
.public-nav-action{display:inline-flex;align-items:center;justify-content:center;padding:.5rem .9rem;border-radius:9999px;border:1px solid var(--border);font-size:.88rem;font-weight:700;color:var(--text)}
.public-nav-action:hover{background:var(--hover)}
.public-nav-action-primary{background:var(--blue);border-color:var(--blue);color:#fff}
.public-nav-action-primary:hover{background:var(--blue2);border-color:var(--blue2)}
main{max-width:760px;margin:0 auto;padding:1.5rem 1rem 3rem}
.hero{margin-bottom:1.25rem}
.hero h1{font-size:1.8rem;font-weight:800;margin-bottom:.35rem}
.hero p{color:var(--text2);max-width:38rem;line-height:1.5}
.members-grid{display:grid;gap:.85rem}
.members-card{display:flex;gap:.85rem;padding:1rem;border:1px solid var(--border);border-radius:16px;background:var(--surface)}
.members-card:hover{background:var(--hover)}
.members-avatar{width:56px;height:56px;border-radius:50%;object-fit:cover;flex-shrink:0}
.members-body{min-width:0;flex:1}
.members-name{font-size:1rem;font-weight:800;color:var(--text)}
.members-handle{font-size:.84rem;color:var(--text2);margin-top:.1rem}
.members-bio{font-size:.88rem;color:var(--text2);line-height:1.45;margin-top:.45rem}
.members-meta{display:flex;gap:1rem;flex-wrap:wrap;font-size:.8rem;color:var(--text3);margin-top:.55rem}
.members-empty{padding:1.25rem;border:1px dashed var(--border);border-radius:16px;color:var(--text2);text-align:center}
</style>
</head>
<body>
<div class="public-nav">
  <a href="/" class="public-nav-brand"><span class="public-nav-brand-symbol">⋰⋱</span><span>Starling</span></a>
  <div class="public-nav-actions">$loginCta$registerCta</div>
</div>
<main>
  <div class="hero">
    <h1>People on this server</h1>
    <p>Browse local profiles published on this Starling instance.</p>
  </div>
  <div class="members-grid">$empty</div>
</main>
</body>
</html>
HTML;
        exit;
    }

    private function collectionPageParam(): int
    {
        $raw = $_GET['page'] ?? null;
        if ($raw === null || $raw === '' || $raw === 'false' || $raw === '0') {
            return 0;
        }
        if ($raw === true || $raw === 'true') {
            return 1;
        }
        $page = (int) $raw;
        return $page > 0 ? $page : 0;
    }

    private function isPubliclyRenderableStatus(?array $status): bool
    {
        return $status !== null
            && in_array((string)($status['visibility'] ?? ''), ['public', 'unlisted'], true)
            && ((string)($status['expires_at'] ?? '') === '' || (string)$status['expires_at'] > now_iso());
    }

    private function formatPollExpiry(?string $iso): ?string
    {
        if (!$iso) return null;
        $ts = strtotime($iso);
        if (!$ts) return substr($iso, 0, 16);
        return date('j M Y, H:i', $ts);
    }

    private function renderTemporaryBadge(?string $expiresAt): string
    {
        if (!$expiresAt) return '';
        $label = $this->formatPollExpiry($expiresAt) ?? $expiresAt;
        return '<span class="temporary-badge" title="Deletes ' . htmlspecialchars($label, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">Temporary</span>';
    }

    private function timeAgoShort(string $iso): string
    {
        $ts = strtotime($iso);
        if (!$ts) return substr($iso, 0, 10);
        $diff = time() - $ts;
        if ($diff < 60) return (string)max(1, (int)round($diff)) . 's';
        if ($diff < 3600) return (string)max(1, (int)round($diff / 60)) . 'm';
        if ($diff < 86400) return (string)max(1, (int)round($diff / 3600)) . 'h';
        if ($diff < 604800) return (string)max(1, (int)round($diff / 86400)) . 'd';
        return date('j M', $ts);
    }

    private function renderPublicCard(array $status): string
    {
        $masto = StatusModel::toMasto($status, null);
        $card = $masto['card'] ?? null;
        if (!$card || empty($card['url']) || !empty($masto['media_attachments'])) return '';
        $img = !empty($card['image'])
            ? '<img src="' . htmlspecialchars((string)$card['image'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '" alt="" loading="lazy">'
            : '';
        $provider = !empty($card['provider_name'])
            ? '<div class="link-card-provider">' . htmlspecialchars((string)$card['provider_name'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</div>'
            : '';
        $desc = !empty($card['description'])
            ? '<div class="link-card-desc">' . htmlspecialchars((string)$card['description'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</div>'
            : '';
        return '<a class="link-card" href="' . htmlspecialchars((string)$card['url'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">'
            . $img
            . '<div class="link-card-body">' . $provider
            . '<div class="link-card-title">' . htmlspecialchars((string)($card['title'] ?? $card['url']), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</div>'
            . $desc . '</div></a>';
    }

    private function renderPublicQuote(array $status): string
    {
        $quote = StatusModel::toMasto($status, null)['quote'] ?? null;
        if (!$quote || empty($quote['account'])) return '';
        $acct = $quote['account'];
        $targetUrl = htmlspecialchars((string)($quote['url'] ?? ('/@' . $acct['username'] . '/' . $quote['id'])), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $mediaBadge = !empty($quote['media_attachments']) ? '<span class="quote-badge">' . count($quote['media_attachments']) . ' media</span>' : '';
        $pollBadge = !empty($quote['poll']) ? '<span class="quote-badge">Poll</span>' : '';
        return '<a class="quote-card" href="' . $targetUrl . '" onclick="event.stopPropagation()">'
            . '<div class="quote-head"><img class="quote-avatar" src="' . htmlspecialchars((string)$acct['avatar'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '" alt="">'
            . '<div class="quote-meta"><strong>' . htmlspecialchars((string)($acct['display_name'] ?: $acct['username']), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</strong><span>@' . htmlspecialchars((string)$acct['acct'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</span></div></div>'
            . '<div class="quote-content">' . ($quote['content'] ?? '<p></p>') . '</div>'
            . (($mediaBadge || $pollBadge) ? '<div class="quote-flags">' . $mediaBadge . $pollBadge . '</div>' : '')
            . '</a>';
    }

    private function renderPublicPoll(string $statusId, string $suffix = ''): string
    {
        $poll = PollModel::byStatusId($statusId);
        if (!$poll) return '';
        $pollData = PollModel::toMasto($poll, null);
        $options = '';
        foreach ($pollData['options'] as $opt) {
            $votes = (int)($opt['votes_count'] ?? 0);
            $pct = (int)$pollData['votes_count'] > 0 ? (int)round(($votes / (int)$pollData['votes_count']) * 100) : 0;
            $options .= '<div class="poll-result">'
                . '<div class="poll-result-bar" style="width:' . $pct . '%"></div>'
                . '<div class="poll-result-row"><span>' . htmlspecialchars((string)($opt['title'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</span><strong>' . $votes . ((int)$pollData['votes_count'] > 0 ? ' · ' . $pct . '%' : '') . '</strong></div>'
                . '</div>';
        }
        $meta = [];
        $meta[] = (bool)$pollData['multiple'] ? 'Multiple choice' : 'Single choice';
        $meta[] = (int)$pollData['votes_count'] . ' votes';
        if (!empty($pollData['expires_at']) && empty($pollData['expired'])) $meta[] = 'Ends ' . $this->formatPollExpiry((string)$pollData['expires_at']);
        if (!empty($pollData['expired'])) $meta[] = 'Closed';
        $pollId = 'poll-results-' . preg_replace('/[^a-zA-Z0-9_-]/', '-', $statusId . '-' . $suffix);
        return '<div class="poll-box">'
            . '<button class="poll-toggle-btn" type="button" onclick="togglePollResults(\'' . $pollId . '\', this);event.stopPropagation()">View results</button>'
            . '<div id="' . htmlspecialchars($pollId, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '" class="poll-results-wrap" style="display:none">'
            . '<div class="poll-options">' . $options . '</div>'
            . '<div class="poll-meta">' . htmlspecialchars(implode(' · ', $meta), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</div>'
            . '</div></div>';
    }

    private function rssItemTitle(array $status, array $owner): string
    {
        $ownerHandle = '@' . $owner['username'] . '@' . AP_DOMAIN;
        if (!empty($status['reblog_of_id'])) {
            $orig = StatusModel::byId((string)$status['reblog_of_id']);
            if ($this->isPubliclyRenderableStatus($orig)) {
                $origHandle = $this->rssAuthorHandle((string)$orig['user_id']);
                return 'Repost by ' . $ownerHandle . ($origHandle !== '' ? ' of ' . $origHandle : '');
            }
            return 'Repost by ' . $ownerHandle;
        }
        if (!empty($status['reply_to_id'])) {
            return 'Reply by ' . $ownerHandle;
        }
        $plain = trim(html_entity_decode(strip_tags((int)($status['local'] ?? 1) ? text_to_html((string)$status['content']) : ensure_html((string)$status['content'])), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        if ($plain === '') return 'Post by ' . $ownerHandle;
        return (function_exists('mb_substr') ? mb_substr($plain, 0, 80) : substr($plain, 0, 80));
    }

    private function rssAuthorHandle(string $userId): string
    {
        $local = DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$userId]);
        if ($local) return '@' . $local['username'] . '@' . AP_DOMAIN;
        $remote = DB::one('SELECT username, domain FROM remote_actors WHERE id=?', [$userId]);
        if ($remote && !empty($remote['username']) && !empty($remote['domain'])) {
            return '@' . $remote['username'] . '@' . $remote['domain'];
        }
        return '';
    }

    private function rssItemDescription(array $status, array $owner): string
    {
        $statusForContent = $status;
        $prefix = '';
        if (!empty($status['reblog_of_id'])) {
            $orig = StatusModel::byId((string)$status['reblog_of_id']);
            if ($this->isPubliclyRenderableStatus($orig)) {
                $statusForContent = $orig;
                $origHandle = $this->rssAuthorHandle((string)$orig['user_id']);
                $prefix = '<p><strong>Reposted by @' . htmlspecialchars($owner['username'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '@' . htmlspecialchars(AP_DOMAIN, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</strong>'
                    . ($origHandle !== '' ? ' &middot; original by ' . htmlspecialchars($origHandle, ENT_QUOTES | ENT_HTML5, 'UTF-8') : '')
                    . '</p>';
            }
        } elseif (!empty($status['reply_to_id'])) {
            $prefix = '<p><strong>Reply by @' . htmlspecialchars($owner['username'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '@' . htmlspecialchars(AP_DOMAIN, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</strong></p>';
        }
        $html = (int)($statusForContent['local'] ?? 1) ? text_to_html((string)$statusForContent['content']) : ensure_html((string)$statusForContent['content']);
        if (trim(strip_tags($html)) === '') {
            $html = '<p>(No text content)</p>';
        }
        return $prefix . $html;
    }

    public function rss(array $p): void
    {
        $u = UserModel::byUsername($p['username']);
        if (!$u) err_out('Not found', 404);

        $rows = DB::all(
            "SELECT * FROM statuses WHERE user_id=? AND visibility IN ('public','unlisted') AND (expires_at IS NULL OR expires_at='' OR expires_at>?) ORDER BY created_at DESC LIMIT 20",
            [$u['id'], now_iso()]
        );

        $profileUrlRaw = ap_url('@' . $u['username']);
        $rssUrlRaw = $profileUrlRaw . '.rss';
        $title = ($u['display_name'] ?: $u['username']) . ' (@' . $u['username'] . '@' . AP_DOMAIN . ')';
        $description = trim((string)($u['bio'] ?? ''));
        if ($description === '') {
            $description = 'Public posts from ' . $title;
        }

        $itemsXml = '';
        foreach ($rows as $s) {
            $boostOrig = null;
            if (!empty($s['reblog_of_id'])) {
                $boostOrig = StatusModel::byId((string)$s['reblog_of_id']);
                if (!$this->isPubliclyRenderableStatus($boostOrig)) {
                    continue;
                }
            }
            $linkRaw = ap_url('@' . $u['username'] . '/' . $s['id']);
            $guidRaw = $linkRaw;
            if (!empty($s['reblog_of_id'])) {
                $orig = $boostOrig;
                if ($orig && (int)($orig['local'] ?? 0) === 1) {
                    $guidRaw = AP_BASE_URL . '/objects/' . rawurlencode((string)$orig['id']);
                } elseif ($orig && !empty($orig['uri'])) {
                    $guidRaw = (string)$orig['uri'];
                }
            }
            $itemTitle = htmlspecialchars($this->rssItemTitle($s, $u), ENT_QUOTES | ENT_XML1, 'UTF-8');
            $itemLink = htmlspecialchars($linkRaw, ENT_QUOTES | ENT_XML1, 'UTF-8');
            $itemGuid = htmlspecialchars($guidRaw, ENT_QUOTES | ENT_XML1, 'UTF-8');
            $itemAuthor = htmlspecialchars($u['username'] . '@' . AP_DOMAIN, ENT_QUOTES | ENT_XML1, 'UTF-8');
            $itemPubDate = htmlspecialchars(date(DATE_RSS, strtotime((string)$s['created_at'])), ENT_QUOTES | ENT_XML1, 'UTF-8');
            $itemDesc = '<![CDATA[' . $this->rssItemDescription($s, $u) . ']]>';
            $itemsXml .= "<item><title>{$itemTitle}</title><link>{$itemLink}</link><guid isPermaLink=\"false\">{$itemGuid}</guid><pubDate>{$itemPubDate}</pubDate><author>{$itemAuthor}</author><description>{$itemDesc}</description></item>";
        }

        $lastBuild = !empty($rows) ? date(DATE_RSS, strtotime((string)$rows[0]['created_at'])) : date(DATE_RSS);
        header('Content-Type: application/rss+xml; charset=utf-8');
        echo '<?xml version="1.0" encoding="UTF-8"?>'
            . '<rss version="2.0"><channel>'
            . '<title>' . htmlspecialchars($title, ENT_QUOTES | ENT_XML1, 'UTF-8') . '</title>'
            . '<link>' . htmlspecialchars($profileUrlRaw, ENT_QUOTES | ENT_XML1, 'UTF-8') . '</link>'
            . '<atom:link xmlns:atom="http://www.w3.org/2005/Atom" href="' . htmlspecialchars($rssUrlRaw, ENT_QUOTES | ENT_XML1, 'UTF-8') . '" rel="self" type="application/rss+xml" />'
            . '<description>' . htmlspecialchars($description, ENT_QUOTES | ENT_XML1, 'UTF-8') . '</description>'
            . '<language>en</language>'
            . '<lastBuildDate>' . htmlspecialchars($lastBuild, ENT_QUOTES | ENT_XML1, 'UTF-8') . '</lastBuildDate>'
            . $itemsXml
            . '</channel></rss>';
        exit;
    }

    public function show(array $p): void
    {
        $u = UserModel::byUsername($p['username']);
        if (!$u) err_out('Not found', 404);

        $accept = strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? ''));
        if (str_contains($accept, 'activity+json')
            || str_contains($accept, 'ld+json')
            || str_contains($accept, 'application/json')) {
            ap_json_out(Builder::actor($u));
        }
        $requestPath = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/');
        if ($requestPath === '/users/' . $u['username']) {
            header('Location: ' . ap_url('@' . $u['username']), true, 301);
            exit;
        }
        // HTML fallback — full profile page
        header('Content-Type: text/html; charset=utf-8');

        $displayName = htmlspecialchars($u['display_name'] ?: $u['username']);
        $username    = htmlspecialchars($u['username']);
        $domain      = AP_DOMAIN;
        $bio         = text_to_html($u['bio'] ?? '');
        $avatar      = htmlspecialchars(local_media_url_or_fallback($u['avatar'] ?? '', '/img/avatar.svg'));
        $headerImg   = htmlspecialchars(local_media_url_or_fallback($u['header'] ?? '', '/img/header.svg'), ENT_QUOTES);
        $followers   = (int)$u['follower_count'];
        $following   = (int)$u['following_count'];
        $statusCount = (int)$u['status_count'];
        $apUrl       = actor_url($u['username']);
        $canonicalProfileUrl = htmlspecialchars(ap_url('@' . $u['username']), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $rssUrl      = htmlspecialchars(ap_url('@' . $u['username'] . '.rss'), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $handle      = htmlspecialchars('@' . $u['username'] . '@' . $domain);
        $v           = AP_VERSION;
        $loginCta = '<a href="/web/login" class="public-nav-action">Log in</a>';
        $registerCta = AP_OPEN_REG ? '<a href="/web/register" class="public-nav-action public-nav-action-primary">Create account</a>' : '';

        // Profile fields (metadata)
        $fields = json_decode($u['fields'] ?? '[]', true) ?: [];
        $fieldsHtml = '';
        foreach ($fields as $field) {
            $name  = htmlspecialchars($field['name'] ?? '');
            $value = \App\Models\UserModel::fieldValueToHtml($field['value'] ?? '');
            $verifiedCls = !empty($field['verified_at']) ? ' profile-field-verified' : '';
            if ($name) $fieldsHtml .= "<div class=\"profile-field\"><span class=\"profile-field-name\">$name</span><span class=\"profile-field-value$verifiedCls\">$value</span></div>";
        }
        if ($fieldsHtml) $fieldsHtml = '<div class="profile-fields">' . $fieldsHtml . '</div>';

        // Build recent activity: posts, replies, boosts — 3 each
        $activities = [];

        $posts = DB::all(
            "SELECT * FROM statuses WHERE user_id=? AND visibility IN ('public','unlisted') AND reblog_of_id IS NULL AND reply_to_id IS NULL AND (expires_at IS NULL OR expires_at='' OR expires_at>?) ORDER BY created_at DESC LIMIT 3",
            [$u['id'], now_iso()]
        );
        $replies = DB::all(
            "SELECT * FROM statuses WHERE user_id=? AND visibility IN ('public','unlisted') AND reblog_of_id IS NULL AND reply_to_id IS NOT NULL AND (expires_at IS NULL OR expires_at='' OR expires_at>?) ORDER BY created_at DESC LIMIT 3",
            [$u['id'], now_iso()]
        );
        $boosts = DB::all(
            "SELECT * FROM statuses WHERE user_id=? AND visibility IN ('public','unlisted') AND reblog_of_id IS NOT NULL AND (expires_at IS NULL OR expires_at='' OR expires_at>?) ORDER BY created_at DESC LIMIT 3",
            [$u['id'], now_iso()]
        );
        foreach ($posts as $s) {
            $activities[] = ['kind' => 'post', 'time' => $s['created_at'], 'row' => $s];
        }
        foreach ($replies as $s) {
            $activities[] = ['kind' => 'reply', 'time' => $s['created_at'], 'row' => $s];
        }
        foreach ($boosts as $s) {
            $activities[] = ['kind' => 'boost', 'time' => $s['created_at'], 'row' => $s];
        }
        usort($activities, fn($a, $b) => strcmp($b['time'], $a['time']));

        // Helper: resolve a user_id to @user@domain
        $getHandle = static function(string $userId): string {
            $local = DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$userId]);
            if ($local) return '@' . $local['username'] . '@' . AP_DOMAIN;
            $remote = DB::one('SELECT username, domain FROM remote_actors WHERE id=?', [$userId]);
            if ($remote) return '@' . $remote['username'] . '@' . $remote['domain'];
            return '';
        };
        $getProfileUrl = static function(string $userId): string {
            $local = DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$userId]);
            if ($local) return ap_url('@' . $local['username']);
            $remote = DB::one('SELECT username, domain, url, id FROM remote_actors WHERE id=?', [$userId]);
            if ($remote) return (string)($remote['url'] ?: (($remote['domain'] && $remote['username']) ? 'https://' . $remote['domain'] . '/@' . ltrim((string)$remote['username'], '@') : ($remote['id'] ?? '')));
            return '';
        };

        // Render a single status card
        $renderCard = function(array $s, string $kind) use ($u, $avatar, $displayName, $getHandle, $getProfileUrl): string {
            $ts = $this->timeAgoShort((string)$s['created_at']);
            $tsTitle = htmlspecialchars(date('j M Y H:i', strtotime((string)$s['created_at'])));
            $ownerProfileUrl = htmlspecialchars(ap_url('@' . $u['username']));
            $orig = null;
            $content = '';
            $attrHandle = '';
            $interactUrlRaw = ap_url('@' . $u['username'] . '/' . $s['id']);

            if ($kind === 'boost' && $s['reblog_of_id']) {
                $orig = DB::one('SELECT * FROM statuses WHERE id=?', [$s['reblog_of_id']]);
                if (!$this->isPubliclyRenderableStatus($orig)) {
                    return '';
                }
                $content = $orig ? ((int)($orig['local'] ?? 0) ? text_to_html($orig['content']) : ensure_html($orig['content'])) : '';
                if ($orig && (int)($orig['local'] ?? 0)) {
                    $origAuthor = DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$orig['user_id']]);
                    $postUrl = $origAuthor
                        ? htmlspecialchars(ap_url('@' . $origAuthor['username'] . '/' . $orig['id']))
                        : htmlspecialchars(ap_url('@' . $u['username'] . '/' . $s['id']));
                } elseif ($orig) {
                    $postUrl = htmlspecialchars(ap_url('@' . $u['username'] . '/' . $s['id']));
                } else {
                    $postUrl = htmlspecialchars(ap_url('@' . $u['username'] . '/' . $s['id']));
                }
                if ($orig) {
                    if ((int)($orig['local'] ?? 0) === 1) {
                        $interactUrlRaw = AP_BASE_URL . '/objects/' . rawurlencode((string)$orig['id']);
                    } else {
                        $interactUrlRaw = (string)(($orig['url'] ?? '') !== '' ? $orig['url'] : ($orig['uri'] ?? $interactUrlRaw));
                    }
                }
            } else {
                $content = (int)($s['local'] ?? 1) ? text_to_html($s['content']) : ensure_html($s['content']);
                $attrHandle = $s['reply_to_uid'] ? $getHandle($s['reply_to_uid']) : '';
                $postUrl = htmlspecialchars(ap_url('@' . $u['username'] . '/' . $s['id']));
            }
            $interactUrl = htmlspecialchars($interactUrlRaw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $contentTextLen = function_exists('mb_strlen') ? mb_strlen(trim(strip_tags($content))) : strlen(trim(strip_tags($content)));
            $truncateContent = $contentTextLen > 600;
            $contentClass = $truncateContent ? 's-content truncated' : 's-content';
            $showMoreBtn = $truncateContent
                ? '<button class="show-more-btn" onclick="event.stopPropagation();toggleExpandedContent(this)">Show more</button>'
                : '';

            // Determine avatar/name
            if ($kind === 'boost' && $orig) {
                $postAuthor = DB::one('SELECT username, display_name, avatar FROM users WHERE id=? AND is_suspended=0', [$orig['user_id']]);
                if ($postAuthor) {
                    $postAvatar = htmlspecialchars(local_media_url_or_fallback($postAuthor['avatar'] ?? '', '/img/avatar.svg'));
                    $postName   = htmlspecialchars($postAuthor['display_name'] ?: $postAuthor['username']);
                    $postAcct   = '@' . htmlspecialchars($postAuthor['username']);
                    $postProfileUrl = htmlspecialchars(ap_url('@' . $postAuthor['username']));
                } else {
                    $ra = DB::one('SELECT username, domain, display_name, avatar, url, id FROM remote_actors WHERE id=?', [$orig['user_id']]);
                    if ($ra) {
                        $postAvatar = htmlspecialchars($ra['avatar'] ?: AP_BASE_URL . '/img/avatar.svg');
                        $postName   = htmlspecialchars($ra['display_name'] ?: $ra['username']);
                        $postAcct   = '@' . htmlspecialchars($ra['username'] . '@' . $ra['domain']);
                        $fallbackRemoteUrl = $ra['domain'] && $ra['username']
                            ? 'https://' . $ra['domain'] . '/@' . ltrim((string)$ra['username'], '@')
                            : (string)($ra['id'] ?? '');
                        $postProfileUrl = htmlspecialchars((string)($ra['url'] ?: $fallbackRemoteUrl));
                    } else {
                        $postAvatar = htmlspecialchars(AP_BASE_URL . '/img/avatar.svg');
                        $postName = $postAcct = '';
                        $postProfileUrl = $postUrl;
                    }
                }
            } else {
                $postAvatar = $avatar;
                $postName   = $displayName;
                $postAcct   = htmlspecialchars('@' . $u['username'] . '@' . AP_DOMAIN);
                $postProfileUrl = htmlspecialchars(ap_url('@' . $u['username']));
            }
            // Boost bar
            $boostBar = $kind === 'boost'
                ? '<div class="boost-bar"><svg viewBox="0 0 24 24" width="16" height="16"><path d="M4.75 3.79l4.603 4.3-1.706 1.82L6 8.38v7.37c0 .97.784 1.75 1.75 1.75H13V19.5H7.75c-2.347 0-4.25-1.9-4.25-4.25V8.38L1.853 9.91.147 8.09l4.603-4.3zm11.5 2.71H11V4.5h5.25c2.347 0 4.25 1.9 4.25 4.25v7.37l1.647-1.53 1.706 1.82-4.603 4.3-4.603-4.3 1.706-1.82L18 16.12V8.75c0-.97-.784-1.75-1.75-1.75z"/></svg> <a href="' . $ownerProfileUrl . '" onclick="event.stopPropagation()">' . $displayName . '</a> reposted</div>'
                : '';

            // Reply indicator
            $replyIndicator = '';
            if ($kind !== 'boost' && $s['reply_to_id']) {
                $replyLabel = $attrHandle ? htmlspecialchars($attrHandle) : '';
                $replyTargetUrl = '';
                $replyParent = \App\Models\StatusModel::byId((string)$s['reply_to_id']);
                if ($replyParent) {
                    if ((int)($replyParent['local'] ?? 0) === 1) {
                        $replyTargetUrl = htmlspecialchars(ap_url('objects/' . rawurlencode((string)$replyParent['id'])));
                    } else {
                        $replyTargetUrl = htmlspecialchars((string)(($replyParent['url'] ?? '') !== '' ? $replyParent['url'] : ($replyParent['uri'] ?? '')));
                    }
                } elseif (str_starts_with((string)$s['reply_to_id'], 'http')) {
                    $replyTargetUrl = htmlspecialchars((string)$s['reply_to_id']);
                } elseif ($s['reply_to_uid']) {
                    $replyTargetUrl = htmlspecialchars($getProfileUrl($s['reply_to_uid']));
                }
                $replyTarget = ($replyLabel && $replyTargetUrl)
                    ? ' to <a class="reply-to-name" href="' . $replyTargetUrl . '" onclick="event.stopPropagation()">' . $replyLabel . '</a>'
                    : ($replyLabel ? ' to ' . $replyLabel : '');
                $replyIndicator = '<div class="reply-indicator"><svg viewBox="0 0 24 24"><path d="M10 9V5l-7 7 7 7v-4.1c5 0 8.5 1.6 11 5.1-1-5-4-10-11-11z"/></svg> Reply' . $replyTarget . '</div>';
            }

            // CW
            $hasCw = (string)($s['cw'] ?? '') !== '';
            $cw = $hasCw
                ? '<div class="cw-bar"><span>⚠ ' . htmlspecialchars($s['cw']) . '</span><button class="cw-toggle" onclick="event.stopPropagation();toggleCWContent(this)">Show more</button></div>'
                : '';
            $cwContentStyle = $hasCw ? ' style="display:none"' : '';

            // Media
            $mediaHtml = '';
            $mediaStatusId = ($kind === 'boost' && $orig) ? $orig['id'] : $s['id'];
            $mediaRows = DB::all(
                'SELECT ma.* FROM media_attachments ma JOIN status_media sm ON sm.media_id=ma.id WHERE sm.status_id=? ORDER BY sm.position LIMIT 4',
                [$mediaStatusId]
            );
            $items = [];
            foreach ($mediaRows as $ma) {
                $murl = htmlspecialchars($ma['url']);
                $alt  = htmlspecialchars($ma['description'] ?? '');
                if ($ma['type'] === 'video') {
                    $items[] = "<div class=\"media-item\"><video src=\"$murl\" controls preload=\"metadata\"></video></div>";
                } else {
                    $altBadge = !empty($ma['description']) ? '<span class="alt-badge">ALT</span>' : '';
                    $items[] = "<div class=\"media-item\"><a href=\"$murl\" target=\"_blank\" rel=\"noopener\"><img src=\"$murl\" alt=\"$alt\" loading=\"lazy\"></a>$altBadge</div>";
                }
            }
            // Action bar counts
            $countStatus = ($kind === 'boost' && $orig) ? $orig : $s;
            $visBadge = (($countStatus['visibility'] ?? 'public') === 'unlisted')
                ? '<span class="vis-icon" title="unlisted"><svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" style="vertical-align:middle"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg></span>'
                : '';
            $mc = count($items);
            if ($mc) $mediaHtml = '<div class="media-grid count-' . $mc . '">' . implode('', $items) . '</div>';
            $mediaSensitive = !empty($countStatus['sensitive']) && $mc > 0;
            $mediaRevealBtn = $mediaSensitive
                ? '<button class="sensitive-overlay" onclick="event.stopPropagation();this.nextElementSibling.style.display=\'\';this.remove()">Sensitive media — click to reveal</button>'
                : '';
            if ($mediaSensitive && $mediaHtml !== '') {
                $mediaHtml = $mediaRevealBtn . '<div style="display:none">' . $mediaHtml . '</div>';
            }
            $pollHtml = $this->renderPublicPoll($mediaStatusId, $kind);

            $dataKind = match($kind) { 'boost' => 'boost', 'reply' => 'reply', default => 'post' };
            $hideStyle = $kind !== 'post' ? ' style="display:none"' : '';

            $cardHtml = $this->renderPublicCard($countStatus);
            $quoteHtml = $this->renderPublicQuote($countStatus);
            $temporaryBadge = $this->renderTemporaryBadge((string)($countStatus['expires_at'] ?? ''));
            $rc = (int)($countStatus['reply_count'] ?? 0);
            $bc = (int)($countStatus['reblog_count'] ?? 0);
            $fc = (int)($countStatus['favourite_count'] ?? 0);
            $rcHtml = $rc > 0 ? '<span class="action-count">' . $rc . '</span>' : '';
            $bcHtml = $bc > 0 ? '<span class="action-count">' . $bc . '</span>' : '';
            $fcHtml = $fc > 0 ? '<span class="action-count">' . $fc . '</span>' : '';

            return <<<CARD
<div class="status-card" data-kind="$dataKind" data-interact-url="$interactUrl"$hideStyle onclick="handleCardClick(event,'$postUrl')">
  $boostBar
  <div class="status-inner">
    <div class="status-left">
      <a href="$postProfileUrl" onclick="event.stopPropagation()"><img class="avatar" src="$postAvatar" alt=""></a>
    </div>
    <div class="status-body">
      <div class="status-header">
        <a class="s-name" href="$postProfileUrl" onclick="event.stopPropagation()">$postName</a>
        <span class="s-acct">$postAcct</span>
        $temporaryBadge
        $visBadge
        <span class="s-middot">·</span>
        <span class="s-time" title="$tsTitle">$ts</span>
      </div>
      $replyIndicator
      $cw
      <div class="cw-content"$cwContentStyle>
        <div class="$contentClass">$content</div>
        $showMoreBtn
        $mediaHtml
        $cardHtml
        $quoteHtml
        $pollHtml
      </div>
      <div class="action-bar">
        <button class="action-btn reply-btn" onclick="event.stopPropagation();showInteract(event)" title="Reply"><svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>$rcHtml</button>
        <button class="action-btn boost-btn" onclick="event.stopPropagation();showInteract(event)" title="Repost"><svg viewBox="0 0 24 24"><path d="M17 1L21 5L17 9V6H7V12H5V6C5 4.9 5.9 4 7 4H17V1ZM7 23L3 19L7 15V18H17V12H19V18C19 19.1 18.1 20 17 20H7V23Z"/></svg>$bcHtml</button>
        <button class="action-btn fav-btn" onclick="event.stopPropagation();showInteract(event)" title="Like"><svg viewBox="0 0 24 24"><path d="M16.5 3c-1.74 0-3.41.81-4.5 2.09C10.91 3.81 9.24 3 7.5 3 4.42 3 2 5.42 2 8.5c0 3.78 3.4 6.86 8.55 11.54L12 21.35l1.45-1.32C18.6 15.36 22 12.28 22 8.5 22 5.42 19.58 3 16.5 3zm-4.4 15.55l-.1.1-.1-.1C7.14 14.24 4 11.39 4 8.5 4 6.5 5.5 5 7.5 5c1.54 0 3.04.99 3.57 2.36h1.87C13.46 5.99 14.96 5 16.5 5c2 0 3.5 1.5 3.5 3.5 0 2.89-3.14 5.74-7.9 10.05z"/></svg>$fcHtml</button>
      </div>
    </div>
  </div>
</div>
CARD;
        };

        $activitiesHtml = '';
        foreach ($activities as $act) {
            $activitiesHtml .= $renderCard($act['row'], $act['kind']);
        }

        if (!$activitiesHtml) {
            $activitiesHtml = '<p class="empty">No public activity yet.</p>';
            $moreHtml       = '';
        } else {
            $moreHtml = <<<MORE
<div class="follow-cta">
  <p class="cta-text">To see more from <strong>$displayName</strong>, follow them on the Fediverse.</p>
  <button class="follow-btn" onclick="document.getElementById('follow-modal').style.display='flex'">
    Follow on Fediverse
  </button>
</div>
MORE;
        }

        $headerBg = $headerImg
            ? "background:url('$headerImg') center/cover no-repeat"
            : 'background:linear-gradient(135deg,#0085FF 0%,#0070E0 100%)';

        $favicon = htmlspecialchars(\site_favicon_url(), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        echo <<<HTML
<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$displayName ($handle)</title>
<link rel="icon" href="$favicon">
<link rel="canonical" href="$canonicalProfileUrl">
<link rel="alternate" type="application/activity+json" href="$apUrl">
<link rel="alternate" type="application/rss+xml" title="$displayName RSS" href="$rssUrl">
<meta property="og:type" content="profile">
<meta property="og:title" content="$displayName ($handle)">
<meta property="og:url" content="$canonicalProfileUrl">
<meta property="og:image" content="$avatar">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#fff;--surface:#fff;--hover:#F3F3F8;--blue:#0085FF;--blue2:#0070E0;--blue-bg:#E0EDFF;
  --border:#E5E7EB;--text:#0F1419;--text2:#66788A;--text3:#8D99A5;
  --green:#20BC07;--red:#EC4040;--pink:#EC4899;--radius:12px;
}
@media(prefers-color-scheme:dark){
  :root{
    --bg:#0A0E14;--surface:#161823;--hover:#1E2030;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--text3:#545864;--blue-bg:#0C1B3A;
    --green:#4ade80;--red:#f87171;--pink:#f472b6
  }
}
body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
.public-nav{max-width:600px;margin:0 auto;border-left:1px solid var(--border);border-right:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.85rem 1rem;border-bottom:1px solid var(--border);background:color-mix(in srgb,var(--surface) 85%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);position:sticky;top:0;z-index:12}
.public-nav-brand{display:flex;align-items:center;gap:.5rem;font-weight:800;color:var(--blue)}
.public-nav-brand-symbol{font-size:1.4rem;line-height:1}
.public-nav-actions{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}
.public-nav-action{display:inline-flex;align-items:center;justify-content:center;padding:.5rem .9rem;border-radius:9999px;border:1px solid var(--border);font-size:.88rem;font-weight:700;color:var(--text);text-decoration:none}
.public-nav-action:hover{text-decoration:none;background:var(--hover)}
.public-nav-action-primary{background:var(--blue);border-color:var(--blue);color:#fff}
.public-nav-action-primary:hover{background:var(--blue2);border-color:var(--blue2);color:#fff}

/* Layout — single column centered like web client */
.col-main{max-width:600px;margin:0 auto;border-left:1px solid var(--border);border-right:1px solid var(--border);min-height:100vh;background:var(--surface)}

/* Profile — exact copy from web client */
.profile-header{border-bottom:1px solid var(--border)}
.profile-banner{height:150px;$headerBg;overflow:hidden}
.profile-banner img{width:100%;height:100%;object-fit:cover;display:block}
.profile-meta{padding:1rem 1.25rem}
.profile-avatar-wrap{margin-top:-48px;margin-bottom:.5rem}
.profile-avatar{
  width:82px;height:82px;border-radius:50%;object-fit:cover;
  border:3px solid var(--surface);display:block
}
.profile-name{font-size:1.3rem;font-weight:800;margin-bottom:.15rem}
.profile-acct{color:var(--text3);font-size:.88rem;margin-bottom:.6rem}
.profile-bio{font-size:.9rem;line-height:1.5;margin-bottom:.75rem}
.profile-bio a{color:var(--blue)}
.profile-fields{margin-bottom:.75rem}
.profile-field{display:flex;gap:.5rem;font-size:.85rem;padding:.35rem 0;border-bottom:1px solid var(--border)}
.profile-field:last-child{border-bottom:none}
.profile-field-name{color:var(--text2);font-weight:600;min-width:80px;flex-shrink:0}
.profile-field-value{color:var(--text);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.profile-field-value a{color:var(--blue)}
.profile-field-verified{color:var(--green)}
.profile-field-verified::before{content:'✓ ';font-weight:700}
.profile-stats{display:flex;gap:1.25rem;font-size:.88rem;color:var(--text3);margin-bottom:.75rem}
.profile-stats strong{color:var(--text);font-weight:700}
.profile-actions{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}

/* Follow button — exact copy from web client */
.follow-btn{
  padding:.45rem 1.1rem;border-radius:9999px;font-weight:600;font-size:.85rem;
  cursor:pointer;transition:all .15s;border:none;
  background:var(--blue);color:#fff;font-family:inherit
}
.follow-btn:hover{opacity:.8}

/* Profile tabs — exact copy from web client */
.profile-tabs{display:flex;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:9;background:color-mix(in srgb,var(--surface) 85%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
.profile-tab{flex:1;padding:.75rem 0;text-align:center;font-size:.88rem;font-weight:500;color:var(--text2);cursor:pointer;border-bottom:2px solid transparent;transition:color .15s;background:none;border-top:none;border-left:none;border-right:none;font-family:inherit}
.profile-tab:hover{color:var(--text)}
.profile-tab.active{color:var(--text);border-bottom:3px solid var(--blue);font-weight:600}

/* Status cards — exact copy from web client */
.status-card{
  padding:.75rem 1rem .6rem;border-top:1px solid var(--border);
  transition:background .12s;display:block;cursor:pointer
}
.status-card:first-child{border-top:none}
.status-card:hover{background:var(--hover)}
.boost-bar{
  display:flex;align-items:center;gap:.4rem;
  font-size:.82rem;color:var(--text2);margin-bottom:.4rem;padding-left:52px
}
.boost-bar svg{width:1rem;height:1rem;fill:var(--green);flex-shrink:0}
.boost-bar a,.boost-bar span{color:var(--text2);font-weight:600}
.boost-bar a:hover{color:var(--blue);text-decoration:underline}
.status-inner{display:flex;gap:.65rem}
.status-left{display:flex;flex-direction:column;align-items:center;gap:4px;position:relative}
.avatar{
  width:42px;height:42px;border-radius:50%;object-fit:cover;
  cursor:pointer;flex-shrink:0;display:block
}
.avatar:hover{opacity:.85}
.status-body{flex:1;min-width:0}
.status-header{
  display:flex;align-items:baseline;gap:.25rem;flex-wrap:nowrap;margin-bottom:.25rem
}
.temporary-badge{display:inline-flex;align-items:center;padding:.12rem .45rem;border-radius:9999px;border:1px solid color-mix(in srgb,var(--amber) 35%,var(--border));background:color-mix(in srgb,var(--amber) 12%,transparent);color:var(--text2);font-size:.72rem;font-weight:700;white-space:nowrap}
.s-name{font-weight:600;font-size:.9rem;white-space:nowrap;
  max-width:60%;overflow:hidden;text-overflow:ellipsis;color:var(--text);text-decoration:none}
.s-name:hover{text-decoration:underline}
.s-acct{font-size:.85rem;color:var(--text3);flex:1;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vis-icon{font-size:.75rem;color:var(--text3);flex-shrink:0}
.s-middot{color:var(--text3);font-size:.85rem;flex-shrink:0}
.s-time{font-size:.85rem;color:var(--text3);white-space:nowrap}

/* Reply indicator — exact copy from web client */
.reply-indicator{font-size:.82rem;color:var(--text3);margin-bottom:.25rem;display:flex;align-items:center;gap:.25rem}
.reply-indicator svg{width:.82rem;height:.82rem;fill:currentColor;flex-shrink:0}
.reply-to-name{color:var(--text2);text-decoration:none}
.reply-to-name:hover{color:var(--blue);text-decoration:underline}

/* Content — exact copy from web client */
.s-content{font-size:.9rem;line-height:1.5;word-break:break-word;margin-bottom:.5rem}
.s-content.truncated{max-height:12rem;overflow:hidden;position:relative}
.s-content.truncated::after{
  content:'';position:absolute;left:0;right:0;bottom:0;height:3rem;
  background:linear-gradient(to bottom,rgba(255,255,255,0),var(--surface))
}
.s-content a{color:var(--blue)}
.s-content a:hover{text-decoration:underline}
.s-content p{margin-bottom:.35rem}
.s-content p:last-child{margin-bottom:0}
.s-content code,.quote-content code{
  display:inline-block;padding:.08rem .38rem;border-radius:6px;
  background:color-mix(in srgb,var(--hover) 70%,var(--surface));
  border:1px solid var(--border);color:var(--text);font-size:.92em;
  font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace
}
.s-content pre,.quote-content pre{
  margin:.55rem 0;padding:.7rem .85rem;border-radius:12px;
  background:color-mix(in srgb,var(--hover) 75%,var(--surface));
  border:1px solid var(--border);overflow:auto
}
.s-content pre code,.quote-content pre code{display:block;padding:0;border:0;background:transparent}
.s-content blockquote,.quote-content blockquote{
  margin:.55rem 0;padding:.15rem 0 .15rem .85rem;
  border-left:3px solid color-mix(in srgb,var(--blue) 35%,var(--border));
  color:var(--text2);background:color-mix(in srgb,var(--hover) 55%,transparent);
  border-radius:0 10px 10px 0
}
.s-content blockquote p,.quote-content blockquote p{margin-bottom:.25rem}
.s-content blockquote p:last-child,.quote-content blockquote p:last-child{margin-bottom:0}
.show-more-btn{
  border:none;background:none;padding:0;margin:0 0 .65rem;
  color:var(--blue);font-size:.84rem;font-weight:700;cursor:pointer;font-family:inherit
}
.show-more-btn:hover{text-decoration:underline}

/* CW bar — exact copy from web client */
.cw-bar{
  background:var(--hover);border:1px solid var(--border);border-radius:8px;
  padding:.4rem .75rem;margin-bottom:.5rem;display:flex;align-items:center;
  justify-content:space-between;gap:.5rem;font-size:.88rem
}
.cw-toggle{
  background:none;border:1px solid var(--border);border-radius:9999px;
  padding:.15rem .6rem;font-size:.78rem;cursor:pointer;
  color:var(--text2);flex-shrink:0;font-family:inherit
}
.cw-toggle:hover{background:var(--blue-bg);border-color:var(--blue);color:var(--blue)}
.sensitive-overlay{
  background:var(--hover);border-radius:10px;padding:1rem;
  text-align:center;margin-bottom:.65rem;cursor:pointer;
  color:var(--text2);font-size:.88rem;border:1px solid var(--border);width:100%;font-family:inherit
}
.sensitive-overlay:hover{background:var(--blue-bg);color:var(--blue)}

/* Media grid — exact copy from web client */
.media-grid{
  display:grid;gap:2px;border-radius:10px;overflow:hidden;
  margin-bottom:.65rem;max-height:380px
}
.media-grid.count-1{grid-template-columns:1fr}
.media-grid.count-2{grid-template-columns:1fr 1fr}
.media-grid.count-3{grid-template-columns:1fr 1fr}
.media-grid.count-3 .media-item:first-child{grid-row:1/3}
.media-grid.count-4{grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr}
.media-item{overflow:hidden;cursor:pointer;background:var(--border);
  display:flex;align-items:center;justify-content:center;min-height:80px;position:relative}
.media-item img,.media-item video{
  width:100%;height:100%;object-fit:cover;display:block}
.media-item a{display:contents}
.alt-badge{
  position:absolute;right:.45rem;bottom:.45rem;
  background:rgba(15,20,25,.82);color:#fff;border-radius:9999px;
  padding:.14rem .42rem;font-size:.68rem;font-weight:700;letter-spacing:.02em
}
.poll-box{margin:.8rem 0;border:1px solid var(--border);border-radius:14px;padding:.8rem;background:var(--hover)}
.poll-options{display:grid;gap:.45rem}
.poll-result{position:relative;overflow:hidden;border:1px solid var(--border);border-radius:9999px;padding:.55rem .8rem;background:var(--surface)}
.poll-result-bar{position:absolute;inset:0 auto 0 0;background:color-mix(in srgb,var(--blue) 12%, transparent)}
.poll-result-row{position:relative;z-index:1;display:flex;justify-content:space-between;gap:.75rem;font-size:.84rem}
.poll-meta{font-size:.78rem;color:var(--text3);margin-top:.55rem}
.poll-toggle-btn{margin-bottom:.65rem;border:1px solid var(--border);background:var(--surface);color:var(--text2);border-radius:9999px;padding:.42rem .9rem;font-weight:700;font-size:.8rem;cursor:pointer;font-family:inherit}
.poll-toggle-btn:hover{background:var(--hover);color:var(--text)}
.quote-card{display:block;border:1px solid var(--border);border-radius:12px;padding:.75rem;margin-bottom:.65rem;background:var(--surface);color:inherit;text-decoration:none}
.quote-card:hover{background:var(--hover);text-decoration:none}
.quote-head{display:flex;align-items:center;gap:.55rem;margin-bottom:.45rem}
.quote-avatar{width:28px;height:28px;border-radius:50%;object-fit:cover;flex-shrink:0}
.quote-meta{display:flex;flex-wrap:wrap;gap:.35rem;font-size:.8rem;color:var(--text3)}
.quote-meta strong{color:var(--text);font-weight:700}
.quote-content{font-size:.86rem;line-height:1.45;word-break:break-word}
.quote-content p{margin-bottom:.25rem}
.quote-content p:last-child{margin-bottom:0}
.quote-flags{display:flex;gap:.4rem;flex-wrap:wrap;margin-top:.5rem}
.quote-badge{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:9999px;padding:.15rem .5rem;font-size:.72rem;color:var(--text2);background:var(--hover)}
.link-card{display:block;border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:.65rem;background:var(--surface);color:inherit;text-decoration:none}
.link-card:hover{background:var(--hover);text-decoration:none}
.link-card img{width:100%;max-height:200px;object-fit:cover;display:block}
.link-card-body{padding:.65rem .85rem}
.link-card-provider{font-size:.75rem;color:var(--text2);margin-bottom:.2rem}
.link-card-title{font-size:.9rem;font-weight:600;color:var(--text);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.link-card-desc{font-size:.8rem;color:var(--text2);margin-top:.2rem;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}

/* Action bar — same as web client */
.action-bar{display:flex;gap:0;margin-top:.4rem;margin-left:-.45rem;max-width:280px}
.action-btn{
  display:inline-flex;align-items:center;gap:.3rem;
  background:none;border:none;cursor:pointer;
  color:var(--text3);font-size:.82rem;padding:.35rem .45rem;
  border-radius:9999px;transition:color .15s;
  flex:1;justify-content:flex-start;font-family:inherit
}
.action-btn svg{width:1.1rem;height:1.1rem;fill:currentColor;flex-shrink:0}
.action-btn:hover{color:var(--text2)}
.action-btn.reply-btn:hover{color:var(--blue)}
.action-btn.boost-btn:hover{color:var(--green)}
.action-btn.fav-btn:hover{color:var(--pink)}
.action-count{font-size:.82rem}

/* CTA */
.follow-cta{padding:1.4rem 1.25rem;text-align:center;border-top:1px solid var(--border)}
.cta-text{color:var(--text2);font-size:.9rem;margin-bottom:1rem}
.empty{color:var(--text2);font-size:.9rem;text-align:center;padding:2.5rem}

/* Server footer */
.server-info{max-width:600px;margin:1.5rem auto 0;text-align:center;padding:.75rem 1rem}
.server-info-links{display:flex;justify-content:center;flex-wrap:wrap;gap:.4rem;margin-bottom:.4rem}
.chip{color:var(--text2);font-size:.78rem;border:1px solid var(--border);padding:.25rem .65rem;border-radius:9999px;background:var(--surface)}
.chip:hover{border-color:var(--blue);color:var(--blue);text-decoration:none}
.server-info-meta{font-size:.75rem;color:var(--text3)}

/* Follow modal */
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:100;align-items:center;justify-content:center}
.modal{background:var(--surface);border-radius:var(--radius);padding:2rem;max-width:380px;width:90%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.12)}
.modal h3{font-size:1.1rem;font-weight:800;margin-bottom:.5rem}
.modal p{color:var(--text2);font-size:.9rem;margin-bottom:1.2rem;line-height:1.5}
.handle-box{font-family:ui-monospace,"SF Mono",monospace;font-size:.9rem;font-weight:700;background:var(--blue-bg);color:var(--blue);padding:.65rem 1.1rem;border-radius:10px;margin-bottom:1.2rem;cursor:pointer;user-select:all;border:2px solid transparent;transition:border-color .15s;word-break:break-all}
.handle-box:hover{border-color:var(--blue)}
.modal-close{color:var(--text2);font-size:.85rem;cursor:pointer;background:none;border:none;margin-top:.75rem;text-decoration:underline}

/* Responsive */
@media(max-width:600px){
  .public-nav{border-left:none;border-right:none}
  .col-main{border-left:none;border-right:none}
}
</style>
</head>
<body>
<div class="public-nav">
  <a href="/" class="public-nav-brand"><span class="public-nav-brand-symbol">⋰⋱</span><span>Starling</span></a>
  <div class="public-nav-actions">$loginCta$registerCta</div>
</div>
<div class="col-main">
  <div class="profile-header">
    <div class="profile-banner"></div>
    <div class="profile-meta">
      <div class="profile-avatar-wrap">
        <img class="profile-avatar" src="$avatar" alt="$displayName">
      </div>
      <div class="profile-name">$displayName</div>
      <div class="profile-acct">$handle</div>
      <div class="profile-bio">$bio</div>
      $fieldsHtml
      <div class="profile-stats">
        <span><strong>$statusCount</strong> posts</span>
        <span><strong>$followers</strong> followers</span>
        <span><strong>$following</strong> following</span>
      </div>
      <div class="profile-actions">
        <button class="follow-btn" onclick="document.getElementById('follow-modal').style.display='flex'">Follow</button>
        <a class="public-nav-action" href="$rssUrl">RSS</a>
      </div>
    </div>
  </div>

  <div class="profile-tabs">
    <button class="profile-tab active" data-ptab="posts" onclick="switchTab(this,'post')">Posts</button>
    <button class="profile-tab" data-ptab="replies" onclick="switchTab(this,'reply')">Replies</button>
    <button class="profile-tab" data-ptab="reposts" onclick="switchTab(this,'boost')">Reposts</button>
  </div>
  <div id="feed">$activitiesHtml</div>
  $moreHtml
</div>

<!-- Server info -->
<div class="server-info">
  <div class="server-info-links">
    <a href="/api/v1/instance" class="chip">API</a>
    <a href="/.well-known/nodeinfo" class="chip">NodeInfo</a>
    <a href="/about" class="chip">About</a>
  </div>
  <div class="server-info-meta">$domain &bull; v$v</div>
</div>

<!-- Follow modal -->
<div class="modal-backdrop" id="follow-modal">
  <div class="modal">
    <h3>Follow $displayName</h3>
    <p>Copy this handle and paste it into the search bar of your Fediverse app (Mastodon, Ivory, Mona, etc.)</p>
    <div class="handle-box" onclick="navigator.clipboard&&navigator.clipboard.writeText(this.innerText).then(()=>{this.style.borderColor='var(--green)'})">$handle</div>
    <br>
    <button class="follow-btn" style="font-size:.85rem" onclick="window.open('https://joinmastodon.org/apps','_blank','noopener,noreferrer')">Get a Fediverse app</button>
    <br>
    <button class="modal-close" onclick="document.getElementById('follow-modal').style.display='none'">Close</button>
  </div>
</div>

<!-- Interact modal -->
<div class="modal-backdrop" id="interact-modal">
  <div class="modal">
    <h3>Interact with this post</h3>
    <p>Copy the post URL and paste it into the search field of your favourite Fediverse app to reply, repost, or like it.</p>
    <div class="handle-box" id="interact-url" onclick="navigator.clipboard&&navigator.clipboard.writeText(this.innerText).then(()=>{this.style.borderColor='var(--green)'})"></div>
    <br>
    <button class="follow-btn" style="font-size:.85rem" onclick="window.open('https://joinmastodon.org/apps','_blank','noopener,noreferrer')">Get a Fediverse app</button>
    <br>
    <button class="modal-close" onclick="document.getElementById('interact-modal').style.display='none'">Close</button>
  </div>
</div>

<script>
document.getElementById('follow-modal').addEventListener('click',function(e){if(e.target===this)this.style.display='none'});
document.getElementById('interact-modal').addEventListener('click',function(e){if(e.target===this)this.style.display='none'});
function handleCardClick(e, url) {
  if (e.target.closest('a') || e.target.closest('button')) return;
  window.location.href = url;
}
function switchTab(btn, kind) {
  document.querySelectorAll('.profile-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.status-card').forEach(card => {
    card.style.display = card.dataset.kind === kind ? '' : 'none';
  });
}
function showInteract(ev) {
  var card = ev && ev.target ? ev.target.closest('.status-card') : null;
  if (!card) return;
  var postUrl = card.getAttribute('data-interact-url') || '';
  if (!postUrl) {
    var url = card.getAttribute('onclick');
    var m = url && url.match(/handleCardClick\(event,'([^']+)'\)/);
    if (m) postUrl = m[1];
  }
  if (postUrl) {
    if (!postUrl.startsWith('http')) postUrl = window.location.origin + postUrl;
    document.getElementById('interact-url').textContent = postUrl;
  }
  document.getElementById('interact-modal').style.display = 'flex';
}
function togglePollResults(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  var open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  if (btn) btn.textContent = open ? 'View results' : 'Hide results';
}
function toggleCWContent(btn) {
  var wrap = btn.closest('.cw-bar')?.nextElementSibling;
  if (!wrap) return;
  var open = wrap.style.display !== 'none';
  wrap.style.display = open ? 'none' : 'block';
  btn.textContent = open ? 'Show more' : 'Show less';
}
function toggleExpandedContent(btn) {
  var body = btn.previousElementSibling;
  if (!body) return;
  var expanded = !body.classList.contains('truncated');
  body.classList.toggle('truncated');
  btn.textContent = expanded ? 'Show more' : 'Show less';
}
</script>
</body></html>
HTML;
        exit;
    }

    public function followers(array $p): void
    {
        $u    = UserModel::byUsername($p['username']);
        if (!$u) err_out('Not found', 404);

        $coll = actor_url($u['username']) . '/followers';
        $page = $this->collectionPageParam();
        $total = (int)(DB::one(
            'SELECT COUNT(*) AS c
               FROM follows f
          LEFT JOIN users lu ON lu.id=f.follower_id
              WHERE f.following_id=? AND f.pending=0
                AND (lu.id IS NULL OR lu.is_suspended=0)',
            [$u['id']]
        )['c'] ?? 0);
        if (!$page) { ap_json_out(Builder::collection($coll, $total)); }

        $rows  = DB::all(
            'SELECT f.follower_id
               FROM follows f
          LEFT JOIN users lu ON lu.id=f.follower_id
              WHERE f.following_id=? AND f.pending=0
                AND (lu.id IS NULL OR lu.is_suspended=0)
           ORDER BY f.created_at DESC
              LIMIT 20 OFFSET ?',
            [$u['id'], ($page-1)*20]
        );
        $items = array_values(array_filter(array_map(function($id) {
            if (!str_starts_with($id, 'http')) {
                $lu = \App\Models\DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$id]);
                return $lu ? actor_url($lu['username']) : null;
            }
            return $id; // remote actor — already an AP URL
        }, array_column($rows, 'follower_id'))));
        ap_json_out(Builder::collectionPage($coll, $page, $items, $total));
    }

    public function following(array $p): void
    {
        $u    = UserModel::byUsername($p['username']);
        if (!$u) err_out('Not found', 404);

        $coll = actor_url($u['username']) . '/following';
        $page = $this->collectionPageParam();
        $total = (int)(DB::one(
            'SELECT COUNT(*) AS c
               FROM follows f
          LEFT JOIN users lu ON lu.id=f.following_id
              WHERE f.follower_id=? AND f.pending=0
                AND (lu.id IS NULL OR lu.is_suspended=0)',
            [$u['id']]
        )['c'] ?? 0);
        if (!$page) { ap_json_out(Builder::collection($coll, $total)); }

        $rows  = DB::all(
            'SELECT f.following_id
               FROM follows f
          LEFT JOIN users lu ON lu.id=f.following_id
              WHERE f.follower_id=? AND f.pending=0
                AND (lu.id IS NULL OR lu.is_suspended=0)
           ORDER BY f.created_at DESC
              LIMIT 20 OFFSET ?',
            [$u['id'], ($page-1)*20]
        );
        $items = array_values(array_filter(array_map(function($id) {
            if (!str_starts_with($id, 'http')) {
                $lu = \App\Models\DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$id]);
                return $lu ? actor_url($lu['username']) : null;
            }
            return $id; // remote actor — already an AP URL
        }, array_column($rows, 'following_id'))));
        ap_json_out(Builder::collectionPage($coll, $page, $items, $total));
    }

    public function outbox(array $p): void
    {
        $u    = UserModel::byUsername($p['username']);
        if (!$u) err_out('Not found', 404);

        $coll  = actor_url($u['username']) . '/outbox';
        $page  = $this->collectionPageParam();
        $total = (int)(DB::one(
            "SELECT COUNT(*) as n FROM statuses s
             WHERE s.user_id=? AND s.visibility IN ('public','unlisted')
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
               AND (
                   s.reblog_of_id IS NULL
                   OR EXISTS (
                       SELECT 1 FROM statuses os
                        WHERE os.id=s.reblog_of_id
                          AND os.visibility IN ('public','unlisted')
                          AND (os.expires_at IS NULL OR os.expires_at='' OR os.expires_at>?)
                   )
               )",
            [$u['id'], now_iso(), now_iso()]
        )['n'] ?? 0);
        if (!$page) { ap_json_out(Builder::collection($coll, $total)); }

        $rows = DB::all(
            "SELECT s.* FROM statuses s
             WHERE s.user_id=? AND s.visibility IN ('public','unlisted')
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
               AND (
                   s.reblog_of_id IS NULL
                   OR EXISTS (
                       SELECT 1 FROM statuses os
                        WHERE os.id=s.reblog_of_id
                          AND os.visibility IN ('public','unlisted')
                          AND (os.expires_at IS NULL OR os.expires_at='' OR os.expires_at>?)
                   )
               )
             ORDER BY s.created_at DESC LIMIT 20 OFFSET ?",
            [$u['id'], now_iso(), now_iso(), ($page-1)*20]
        );
        $items = array_map(function ($s) use ($u) {
            if (!empty($s['reblog_of_id'])) {
                $orig = \App\Models\StatusModel::byId($s['reblog_of_id']);
                return $this->isPubliclyRenderableStatus($orig) ? Builder::announce($s, $orig, $u) : null;
            }
            return Builder::create($s, $u);
        }, $rows);
        $items = array_values(array_filter($items));
        ap_json_out(Builder::collectionPage($coll, $page, $items, $total));
    }

    public function featured(array $p): void
    {
        $u = UserModel::byUsername($p['username']);
        if (!$u) err_out('Not found', 404);

        $url  = actor_url($u['username']) . '/featured';
        $pins = DB::all(
            'SELECT s.* FROM statuses s
             JOIN status_pins sp ON sp.status_id=s.id
             WHERE sp.user_id=?
               AND s.visibility IN (\'public\',\'unlisted\')
               AND (s.expires_at IS NULL OR s.expires_at=\'\' OR s.expires_at>?)
             ORDER BY sp.created_at DESC',
            [$u['id'], now_iso()]
        );

        $items = array_map(fn($s) => Builder::note($s, $u), $pins);

        ap_json_out([
            '@context'   => 'https://www.w3.org/ns/activitystreams',
            'id'         => $url,
            'type'       => 'OrderedCollection',
            'totalItems' => count($items),
            'orderedItems' => $items,
        ]);
    }

    public function inbox(array $p): void
    {
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
        rate_limit_enforce('user_inbox_ip:' . client_ip(), 120, 300, 'Rate limit exceeded for inbox');
        rate_limit_enforce('user_inbox_actor:' . $actorHost, 120, 300, 'Rate limit exceeded for inbox');

        $headers = get_request_headers();
        $path    = (string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        $query   = (string)parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_QUERY);
        if ($query !== '') $path .= '?' . $query;

        InboxProcessor::process($activity, $headers, 'POST', $path, $raw, [
            'method' => 'POST',
            'path' => $path,
            'host' => (string)($_SERVER['HTTP_HOST'] ?? ''),
            'remote_ip' => client_ip(),
        ]);

        defer_after_response(static function (): void {
            if (throttle_allow('delivery_retry_queue', 10)) {
                \App\ActivityPub\Delivery::processRetryQueue(\App\ActivityPub\Delivery::inboxDrainBatch());
            }
        });

        http_response_code(202);
        header('Content-Type: application/activity+json');
        echo '{"status":"accepted"}';
        exit;
    }
}
