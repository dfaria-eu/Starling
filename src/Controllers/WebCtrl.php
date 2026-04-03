<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Models\{DB, UserModel, Schema, StatusModel, PollModel, AdminModel};

class WebCtrl
{
    private function generatedConfigPath(): string
    {
        return ROOT . '/storage/config.generated.php';
    }

    private function writeGeneratedConfig(array $config): void
    {
        $path = $this->generatedConfigPath();
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        $php = "<?php\nreturn " . var_export($config, true) . ";\n";
        if (@file_put_contents($path, $php, LOCK_EX) === false) {
            throw new \RuntimeException('Could not write the generated configuration file.');
        }
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
        return '<a class="link-card" href="' . htmlspecialchars((string)$card['url'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '" target="_blank" rel="noopener noreferrer">'
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
        return '<a class="quote-card" href="' . $targetUrl . '">'
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
            . '<button class="poll-toggle-btn" type="button" onclick="togglePollResults(\'' . $pollId . '\', this)">View results</button>'
            . '<div id="' . htmlspecialchars($pollId, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '" class="poll-results-wrap" style="display:none">'
            . '<div class="poll-options">' . $options . '</div>'
            . '<div class="poll-meta">' . htmlspecialchars(implode(' · ', $meta), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</div>'
            . '</div></div>';
    }

    private function startInstallSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_name('ap_install');
            session_set_cookie_params(['path' => '/install', 'secure' => is_https_request(), 'httponly' => true, 'samesite' => 'Strict']);
            session_start();
        }
    }

    private function installEnabled(): bool
    {
        if (defined('AP_ALLOW_INSTALL') && AP_ALLOW_INSTALL) return true;
        if (AP_DEBUG) return true;
        return is_file(ROOT . '/storage/.allow-install');
    }

    public function home(array $p): void
    {
        $users  = DB::count('users', 'is_suspended=0');
        $posts  = (int)(DB::one(
            "SELECT COUNT(*) c FROM statuses
             WHERE local=1
               AND user_id NOT IN (SELECT id FROM users WHERE is_suspended=1)
               AND (expires_at IS NULL OR expires_at='' OR expires_at>?)",
            [now_iso()]
        )['c'] ?? 0);
        $domain = AP_DOMAIN;
        $name   = htmlspecialchars(AP_NAME);
        $desc   = htmlspecialchars(AP_DESCRIPTION);
        $v      = AP_VERSION;
        $open   = AP_OPEN_REG ? 'Open' : 'Closed';
        $openCls = AP_OPEN_REG ? 'green' : 'muted';

        // Use first admin user (or first user) for WebFinger demo link
        $adminUser = DB::one('SELECT username FROM users WHERE is_admin=1 AND is_suspended=0 ORDER BY created_at ASC LIMIT 1')
                  ?? DB::one('SELECT username FROM users WHERE is_suspended=0 ORDER BY created_at ASC LIMIT 1');
        $wfUser = $adminUser ? htmlspecialchars($adminUser['username']) : 'admin';
        $wfAcct = htmlspecialchars($wfUser . '@' . $domain);

        // Featured profiles
        $featuredUsers = DB::all('SELECT username, display_name, avatar, bio, follower_count FROM users WHERE is_suspended=0 ORDER BY follower_count DESC, created_at ASC LIMIT 4');
        $recentPosts = DB::all(
            "SELECT s.id, s.content, s.cw, s.created_at, s.reblog_of_id, s.reply_to_id, s.user_id,
                    u.username, u.display_name, u.avatar
             FROM statuses s
             JOIN users u ON u.id = s.user_id
             WHERE s.local=1 AND s.visibility IN ('public','unlisted') AND u.is_suspended=0
               AND (s.expires_at IS NULL OR s.expires_at='' OR s.expires_at>?)
             ORDER BY s.created_at DESC
             LIMIT 3"
            ,
            [now_iso()]
        );
        $loginCta = '<a href="/web/login" class="nav-action">Log in</a>';
        $registerCta = AP_OPEN_REG ? '<a href="/web/register" class="nav-action nav-action-primary">Create account</a>' : '';
        $heroRegisterCta = AP_OPEN_REG ? '<a href="/web/register" class="btn">Create account</a>' : '';
        $heroLoginCta = '<a href="/web/login" class="btn ' . (AP_OPEN_REG ? 'btn-outline' : '') . '">Log in</a>';

        header('Content-Type: text/html; charset=utf-8');
        echo <<<HTML
<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$name</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text x=%2250%25%22 y=%2252%25%22 text-anchor=%22middle%22 dominant-baseline=%22middle%22 font-size=%2244%22 font-family=%22Arial,sans-serif%22>⋰⋱</text></svg>">
<meta name="description" content="$desc">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--blue:#0085FF;--blue2:#0070E0;--bg:#fff;--surface:#fff;--hover:#F3F3F8;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--text3:#8D99A5;--green:#20BC07;--blue-bg:#E0EDFF}
@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--hover:#1E2030;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--text3:#545864;--blue-bg:#0C1B3A}}
body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
nav{background:color-mix(in srgb,var(--surface) 85%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:.75rem 1.5rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;position:sticky;top:0;z-index:10}
nav .nav-brand{display:flex;align-items:center;gap:.5rem}
nav .fedi-symbol{font-size:1.4rem;color:var(--blue);line-height:1}
nav .logo{font-size:1.1rem;font-weight:800;color:var(--blue);text-decoration:none}
nav .nav-actions{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
nav .nav-action{display:inline-flex;align-items:center;justify-content:center;padding:.55rem .95rem;border-radius:9999px;border:1px solid var(--border);color:var(--text);font-size:.9rem;font-weight:700;text-decoration:none}
nav .nav-action:hover{text-decoration:none;background:var(--hover)}
nav .nav-action-primary{background:var(--blue);border-color:var(--blue);color:#fff}
nav .nav-action-primary:hover{background:var(--blue2);border-color:var(--blue2);color:#fff}
main{max-width:900px;margin:0 auto;padding:2rem 1rem}
.hero{text-align:center;padding:3rem 1rem 2.5rem;border-bottom:1px solid var(--border);margin-bottom:2.5rem}
.hero h1{font-size:2.5rem;font-weight:800;letter-spacing:-.03em;margin-bottom:.6rem}
.hero p{color:var(--text2);font-size:1.1rem;max-width:480px;margin:0 auto 1.8rem}
.hero-subcopy{font-size:.98rem!important;max-width:620px!important;margin:-.9rem auto 1.4rem!important;color:var(--text3)!important;line-height:1.55}
.hero-subcopy strong{color:var(--blue);font-weight:800}
.hero-actions{display:flex;justify-content:center;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem}
.btn{display:inline-flex;align-items:center;gap:.4rem;background:var(--blue);color:#fff;font-weight:700;font-size:.95rem;padding:.65rem 1.4rem;border-radius:9999px;border:none;cursor:pointer;text-decoration:none;transition:background .15s}
.btn:hover{background:var(--blue2);text-decoration:none;color:#fff}
.btn-outline{background:transparent;color:var(--blue);border:1.5px solid var(--blue)}
.btn-outline:hover{background:var(--blue-bg);color:var(--blue)}
.server-handle{display:inline-block;background:var(--blue-bg);color:var(--blue);font-weight:700;font-size:.95rem;padding:.45rem 1.1rem;border-radius:9999px;margin-bottom:1.8rem;cursor:pointer;user-select:all;letter-spacing:.01em}
.stats-row{display:flex;justify-content:center;gap:2.5rem;margin-bottom:2.5rem}
.stat{text-align:center}
.stat .n{font-size:1.9rem;font-weight:800;color:var(--text)}
.stat .l{font-size:.85rem;color:var(--text2);margin-top:.1rem}
.stat.green .n{color:var(--green)}
.stat.muted .n{color:var(--text2)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;margin-bottom:2rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1.25rem 1.4rem}
.card-full{grid-column:1 / -1}
.card-title{font-size:.75rem;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.07em;margin-bottom:.9rem}
.profile-row{display:flex;align-items:center;gap:.75rem;padding:.5rem 0;border-bottom:1px solid var(--border)}
.profile-row:last-child{border-bottom:0}
.p-avatar{width:40px;height:40px;border-radius:50%;object-fit:cover;flex-shrink:0}
.p-name{font-weight:700;font-size:.9rem}
.p-handle{font-size:.8rem;color:var(--text2)}
.links-row{display:flex;flex-wrap:wrap;gap:.5rem}
.post-row{display:block;padding:.8rem 0;border-bottom:1px solid var(--border);color:inherit;text-decoration:none}
.post-row:last-child{border-bottom:0}
.post-row:hover{text-decoration:none;background:transparent}
.post-meta{display:flex;align-items:center;gap:.55rem;margin-bottom:.45rem}
.post-avatar{width:32px;height:32px;border-radius:50%;object-fit:cover;flex-shrink:0}
.post-author{font-size:.86rem;font-weight:700;color:var(--text)}
.post-time{font-size:.78rem;color:var(--text3)}
.post-kind{display:inline-flex;align-items:center;margin-left:.35rem;padding:.08rem .42rem;border-radius:9999px;border:1px solid var(--border);background:var(--hover);color:var(--text2);font-size:.72rem;font-weight:700}
.post-snippet{font-size:.9rem;color:var(--text2);line-height:1.45;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.chip{display:inline-block;color:var(--text2);font-size:.82rem;font-weight:500;padding:.38rem .85rem;border-radius:9999px;border:1px solid var(--border);background:var(--hover)}
.chip:hover{border-color:var(--blue);color:var(--blue);text-decoration:none}
.connect-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1.5rem;text-align:center;margin-bottom:2rem}
.connect-box h2{font-size:1.1rem;font-weight:700;margin-bottom:.4rem}
.connect-box p{color:var(--text2);font-size:.9rem;margin-bottom:1rem}
.handle-copy{font-family:monospace;font-size:.95rem;background:var(--blue-bg);color:var(--blue);padding:.4rem .9rem;border-radius:8px;user-select:all;display:inline-block;margin-bottom:1rem}
footer{text-align:center;padding:2rem;color:var(--text2);font-size:.8rem;border-top:1px solid var(--border)}
@media(max-width:640px){nav{padding:.75rem 1rem}.hero h1{font-size:2.1rem}.stats-row{gap:1.25rem;flex-wrap:wrap}}
</style>
</head>
<body>
<nav>
  <div class="nav-brand">
    <span class="fedi-symbol">⋰⋱</span>
    <a class="logo" href="/">Starling</a>
  </div>
  <div class="nav-actions">
    $loginCta
    $registerCta
  </div>
</nav>
<main>
  <div class="hero">
    <h1>A place on the fediverse</h1>
    <p>$name is an ActivityPub server. Post, follow, and interact across Mastodon, Misskey, Pleroma, GoToSocial, PixelFed, and other federated platforms.</p>
    <p class="hero-subcopy">Inspired by <strong>starling</strong> murmurations: decentralized, leaderless, and shaped by nearby connection.</p>
    <div class="hero-actions">
      $heroRegisterCta
      $heroLoginCta
    </div>
    <div class="stats-row">
      <div class="stat"><div class="n">$users</div><div class="l">Members</div></div>
      <div class="stat"><div class="n">$posts</div><div class="l">Posts</div></div>
      <div class="stat $openCls"><div class="n">$open</div><div class="l">Registration</div></div>
    </div>
    <a href="https://joinmastodon.org/apps" target="_blank" rel="noopener" class="btn">Connect with a Fediverse app</a>
  </div>

HTML;

        // Featured profiles
        if ($featuredUsers) {
            $profileRows = '';
            foreach ($featuredUsers as $fu) {
                $fuName   = htmlspecialchars($fu['display_name'] ?: $fu['username']);
                $fuHandle = htmlspecialchars('@' . $fu['username'] . '@' . $domain);
                $fuAvatar = htmlspecialchars(local_media_url_or_fallback($fu['avatar'] ?? '', '/img/avatar.svg'));
                $fuUrl    = htmlspecialchars(ap_url('users/' . $fu['username']));
                $profileRows .= <<<ROW
<a href="$fuUrl" class="profile-row" style="text-decoration:none;color:inherit;display:flex;align-items:center;gap:.75rem;padding:.55rem 0;border-bottom:1px solid var(--border)">
  <img class="p-avatar" src="$fuAvatar" alt="">
  <div>
    <div class="p-name">$fuName</div>
    <div class="p-handle">$fuHandle</div>
  </div>
</a>
ROW;
            }
            echo <<<SECTION
  <div class="grid">
    <div class="card">
      <div class="card-title">People on this server</div>
      $profileRows
    </div>
SECTION;
        }

        if ($recentPosts) {
            $recentRows = '';
            foreach ($recentPosts as $rp) {
                $displayPost = $rp;
                $displayNameRaw = (string)($rp['display_name'] ?: $rp['username']);
                $displayAvatarRaw = (string)($rp['avatar'] ?? '');
                $kindIcon = '•';
                $kindLabel = 'Post';
                $postUrlRaw = ap_url('@' . $rp['username'] . '/' . $rp['id']);

                if (!empty($rp['reblog_of_id'])) {
                    $kindIcon = '↻';
                    $kindLabel = 'Repost';
                    $orig = StatusModel::byId((string)$rp['reblog_of_id']);
                    if ($orig) {
                        $displayPost = $orig;
                        if ((int)($orig['local'] ?? 0) === 1) {
                            $origAuthor = DB::one(
                                'SELECT username, display_name, avatar FROM users WHERE id=? AND is_suspended=0',
                                [$orig['user_id']]
                            );
                            if ($origAuthor) {
                                $displayNameRaw = (string)($origAuthor['display_name'] ?: $origAuthor['username']);
                                $displayAvatarRaw = (string)($origAuthor['avatar'] ?? '');
                            }
                        } else {
                            $remoteAuthor = DB::one(
                                'SELECT username, display_name, avatar FROM remote_actors WHERE id=?',
                                [$orig['user_id']]
                            );
                            if ($remoteAuthor) {
                                $displayNameRaw = (string)($remoteAuthor['display_name'] ?: $remoteAuthor['username']);
                                $displayAvatarRaw = (string)($remoteAuthor['avatar'] ?? '');
                            }
                        }
                    }
                } elseif (!empty($rp['reply_to_id'])) {
                    $kindIcon = '↩';
                    $kindLabel = 'Reply';
                }

                $postAvatar = htmlspecialchars(local_media_url_or_fallback($displayAvatarRaw, '/img/avatar.svg'));
                $postName = htmlspecialchars($displayNameRaw);
                $postUrl = htmlspecialchars($postUrlRaw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $postTime = htmlspecialchars(date('j M · H:i', strtotime((string)$rp['created_at'])));
                $postKind = htmlspecialchars($kindIcon . ' ' . $kindLabel, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $snippetHtml = (int)($displayPost['local'] ?? 1) === 1
                    ? text_to_html((string)($displayPost['content'] ?? ''))
                    : ensure_html((string)($displayPost['content'] ?? ''));
                $snippetSource = trim((string)(($displayPost['cw'] ?? '') ?: strip_tags($snippetHtml)));
                $snippet = htmlspecialchars(mb_substr($snippetSource, 0, 180), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $recentRows .= <<<ROW
<a href="$postUrl" class="post-row">
  <div class="post-meta">
    <img class="post-avatar" src="$postAvatar" alt="">
    <div>
      <div class="post-author">$postName</div>
      <div class="post-time">$postTime <span class="post-kind">$postKind</span></div>
    </div>
  </div>
  <div class="post-snippet">$snippet</div>
</a>
ROW;
            }
            echo <<<SECTION
    <div class="card">
      <div class="card-title">Latest public posts</div>
      $recentRows
    </div>
SECTION;
        }

        echo <<<HTML
    <div class="card card-full">
      <div class="card-title">Server info</div>
      <div class="links-row">
        <a href="/api/v1/instance" class="chip">API</a>
        <a href="/.well-known/nodeinfo" class="chip">NodeInfo</a>
        <a href="/.well-known/webfinger?resource=acct:$wfAcct" class="chip">WebFinger</a>
        <a href="/about" class="chip">About</a>
      </div>
      <p style="font-size:.8rem;color:var(--text2);margin-top:1rem">Server: <strong>$domain</strong> &bull; Software: <strong>Starling</strong> v$v</p>
    </div>
  </div>

  <div class="connect-box">
    <h2>Join the conversation</h2>
    <p>Use the web client to sign in, or open your Fediverse app and search for this server to find people to follow.</p>
    <div class="handle-copy">$domain</div>
    <br>
    $heroLoginCta
HTML;
        if (AP_OPEN_REG) {
            echo ' <a href="/web/register" class="btn" style="font-size:.85rem">Create account</a>';
        }
        echo <<<HTML
    <br><br>
    <a href="https://joinmastodon.org/apps" target="_blank" rel="noopener" class="btn btn-outline" style="font-size:.85rem">Get a Fediverse app &rarr;</a>
  </div>
</main>
<footer>$name &bull; ActivityPub server v$v &bull; <a href="https://www.w3.org/TR/activitypub/">ActivityPub</a></footer>
</body></html>
HTML;
        exit;
    }

    public function profile(array $p): void
    {
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        if (str_contains($accept, 'activity+json') || str_contains($accept, 'ld+json')) {
            $user = UserModel::byUsername($p['username'] ?? '');
            if (!$user) err_out('Not found', 404);
            ap_json_out(\App\ActivityPub\Builder::actor($user));
        }
        header('Location: ' . ap_url('users/' . rawurlencode($p['username'])), true, 301);
        exit;
    }

    public function status(array $p): void
    {
        $username = $p['username'] ?? '';
        $id       = $p['id'] ?? '';

        $user = UserModel::byUsername($username);
        $s    = $user ? StatusModel::byId($id) : null;

        if (!$user || !$s || $s['user_id'] !== $user['id']
            || !in_array($s['visibility'], ['public', 'unlisted'])) {
            // Check for tombstone (deleted post) — return 410 Gone
            $uri = ap_url('objects/' . $id);
            $tomb = DB::one('SELECT deleted_at FROM tombstones WHERE uri=?', [$uri]);
            $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
            if ($tomb && (str_contains($accept, 'activity+json') || str_contains($accept, 'ld+json'))) {
                ap_json_out([
                    '@context' => 'https://www.w3.org/ns/activitystreams',
                    'type'     => 'Tombstone',
                    'id'       => $uri,
                    'deleted'  => $tomb['deleted_at'],
                ], 410);
            }
            http_response_code($tomb ? 410 : 404);
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html><html><head><meta charset=utf-8><title>' . ($tomb ? '410' : '404') . '</title></head><body><h1>Post not found</h1></body></html>';
            exit;
        }

        // Content negotiation: serve ActivityPub JSON when requested (Mastodon search, etc.)
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        if (str_contains($accept, 'activity+json') || str_contains($accept, 'ld+json')) {
            if (!empty($s['reblog_of_id'])) {
                $orig = StatusModel::byId((string)$s['reblog_of_id']);
                if ($orig) {
                    ap_json_out(\App\ActivityPub\Builder::announce($s, $orig, $user));
                }
            }
            $note = \App\ActivityPub\Builder::note($s, $user);
            $note = ['@context' => \App\ActivityPub\Builder::getContext()] + $note;
            ap_json_out($note);
        }

        $domain = AP_DOMAIN;
        $name   = htmlspecialchars(AP_NAME);
        $activityPubUrlRaw = (string)($displayStatus['uri'] ?? $s['uri'] ?? '');

        // For boosts, show the original post's content and author
        if ($s['reblog_of_id']) {
            $orig = StatusModel::byId($s['reblog_of_id']);
            if ($orig) {
                // Redirect to the original post if it's local, or show its content
                if ((int)($orig['local'] ?? 0)) {
                    $origAuthor = DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$orig['user_id']]);
                    if ($origAuthor) {
                        header('Location: ' . ap_url('@' . $origAuthor['username'] . '/' . $orig['id']), true, 302);
                        exit;
                    }
                }
                // Remote original: show it inline
                $displayStatus = $orig;
            } else {
                $displayStatus = $s;
            }
        } else {
            $displayStatus = $s;
        }

        $displayExpiresAt = (string)($displayStatus['expires_at'] ?? '');
        if ($displayExpiresAt !== '' && strtotime($displayExpiresAt) !== false && strtotime($displayExpiresAt) <= time()) {
            if ((int)($displayStatus['local'] ?? 0) === 1) {
                StatusModel::delete((string)$displayStatus['id'], (string)$displayStatus['user_id']);
            }
            http_response_code(410);
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html><html><head><meta charset=utf-8><title>410</title></head><body><h1>Post not found</h1></body></html>';
            exit;
        }

        $ownerProfileUrlRaw = ap_url('users/' . $user['username']);
        $displayProfileUrlRaw = $ownerProfileUrlRaw;
        $displayNameRaw = (string)($user['display_name'] ?: $user['username']);
        $displayAcctRaw = '@' . $user['username'] . '@' . $domain;
        $displayAvatarRaw = (string)($user['avatar'] ?? '');
        $boostHtml = '';

        if ($s['reblog_of_id'] && !empty($displayStatus['user_id'])) {
            if ((int)($displayStatus['local'] ?? 0) === 1) {
                $displayAuthor = DB::one('SELECT username, display_name, avatar FROM users WHERE id=? AND is_suspended=0', [$displayStatus['user_id']]);
                if ($displayAuthor) {
                    $displayNameRaw = (string)($displayAuthor['display_name'] ?: $displayAuthor['username']);
                    $displayAcctRaw = '@' . $displayAuthor['username'] . '@' . $domain;
                    $displayAvatarRaw = (string)($displayAuthor['avatar'] ?? '');
                    $displayProfileUrlRaw = ap_url('users/' . $displayAuthor['username']);
                }
            } else {
                $displayRemote = DB::one('SELECT username, display_name, avatar, domain, url, id FROM remote_actors WHERE id=?', [$displayStatus['user_id']]);
                if ($displayRemote) {
                    $displayNameRaw = (string)($displayRemote['display_name'] ?: $displayRemote['username']);
                    $displayAcctRaw = '@' . $displayRemote['username'] . '@' . $displayRemote['domain'];
                    $displayAvatarRaw = (string)($displayRemote['avatar'] ?? '');
                    $displayProfileUrlRaw = (string)($displayRemote['url'] ?: (($displayRemote['domain'] && $displayRemote['username']) ? 'https://' . $displayRemote['domain'] . '/@' . ltrim((string)$displayRemote['username'], '@') : ($displayRemote['id'] ?? '')));
                }
            }

            $boostHtml = '<div class="reply-indicator"><svg viewBox="0 0 24 24"><path d="M17 1L21 5L17 9V6H7V12H5V6C5 4.9 5.9 4 7 4H17V1ZM7 23L3 19L7 15V18H17V12H19V18C19 19.1 18.1 20 17 20H7V23Z"/></svg> Reposted by <a class="reply-to-name" href="' . htmlspecialchars(ap_url('users/' . $user['username']), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">@' . htmlspecialchars($user['username'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '@' . htmlspecialchars($domain, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</a></div>';
        }

        $uname      = htmlspecialchars($displayNameRaw);
        $acct       = htmlspecialchars($displayAcctRaw);
        $avatar     = htmlspecialchars(local_media_url_or_fallback($displayAvatarRaw, '/img/avatar.svg'));
        $ownerProfileUrl = htmlspecialchars($ownerProfileUrlRaw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $profileUrl = htmlspecialchars($displayProfileUrlRaw);
        $contentRaw = (int)($displayStatus['local'] ?? 1) ? text_to_html($displayStatus['content']) : ensure_html($displayStatus['content']);
        $ts         = htmlspecialchars($s['created_at']);
        $visBadge   = ($displayStatus['visibility'] ?? 'public') === 'unlisted'
            ? '<span class="vis-icon" title="unlisted"><svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" style="vertical-align:middle"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg></span>'
            : '';
        $metaVis = $visBadge ? '<span>&middot;</span>' . $visBadge : '';

        // Reply info
        $replyHtml = '';
        if (!empty($displayStatus['reply_to_id'])) {
            $replyToHandle = '';
            $replyToUrl = '';
            $replyTargetUrl = '';
            $replyTargetId = (string)$displayStatus['reply_to_id'];
            $replyParent = StatusModel::byId($replyTargetId);
            if ($replyParent) {
                if ((int)($replyParent['local'] ?? 0) === 1) {
                    $replyTargetUrl = ap_url('objects/' . rawurlencode((string)$replyParent['id']));
                } else {
                    $replyTargetUrl = (string)(($replyParent['url'] ?? '') !== '' ? $replyParent['url'] : ($replyParent['uri'] ?? ''));
                }
            } elseif (str_starts_with($replyTargetId, 'http')) {
                $replyTargetUrl = $replyTargetId;
            }
            if (!empty($displayStatus['reply_to_uid'])) {
                $rl = DB::one('SELECT username FROM users WHERE id=? AND is_suspended=0', [$displayStatus['reply_to_uid']]);
                if ($rl) {
                    $replyToHandle = '@' . $rl['username'] . '@' . $domain;
                    $replyToUrl = ap_url('@' . $rl['username']);
                } else {
                    $rr = DB::one('SELECT username, domain, url, id FROM remote_actors WHERE id=?', [$displayStatus['reply_to_uid']]);
                    if ($rr) {
                        $replyToHandle = '@' . $rr['username'] . '@' . $rr['domain'];
                        $replyToUrl = (string)($rr['url'] ?: (($rr['domain'] && $rr['username']) ? 'https://' . $rr['domain'] . '/@' . ltrim((string)$rr['username'], '@') : ($rr['id'] ?? '')));
                    }
                }
            }
            $replyLabel = $replyToHandle ? htmlspecialchars($replyToHandle) : '';
            $replyHref = $replyTargetUrl !== '' ? $replyTargetUrl : $replyToUrl;
            $replyTarget = ($replyLabel && $replyHref)
                ? ' to <a class="reply-to-name" href="' . htmlspecialchars($replyHref, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">' . $replyLabel . '</a>'
                : ($replyLabel ? ' to ' . $replyLabel : '');
            $replyHtml = '<div class="reply-indicator"><svg viewBox="0 0 24 24"><path d="M10 9V5l-7 7 7 7v-4.1c5 0 8.5 1.6 11 5.1-1-5-4-10-11-11z"/></svg> Reply' . $replyTarget . '</div>';
        }

        // OG description — strip HTML tags from content
        $ogDesc = htmlspecialchars(mb_substr(strip_tags($displayStatus['content'] ?? ''), 0, 200));
        if ($displayStatus['cw']) {
            $ogDesc = htmlspecialchars($displayStatus['cw']);
        }

        // OG image — first media attachment, fallback to avatar
        $ogImage = $avatar;
        $mediaItems = DB::all(
            'SELECT ma.url, ma.type, ma.description FROM media_attachments ma JOIN status_media sm ON sm.media_id=ma.id WHERE sm.status_id=? ORDER BY sm.position',
            [$displayStatus['id']]
        );
        if ($mediaItems && !empty($mediaItems[0]['url'])) {
            $ogImage = htmlspecialchars($mediaItems[0]['url']);
        }

        $canonicalUrlRaw = AP_BASE_URL . '/@' . $user['username'] . '/' . $s['id'];
        $interactUrlRaw = $canonicalUrlRaw;
        if (!empty($s['reblog_of_id'])) {
            if ((int)($displayStatus['local'] ?? 0) === 1) {
                $interactUrlRaw = AP_BASE_URL . '/objects/' . rawurlencode((string)$displayStatus['id']);
            } elseif (!empty($displayStatus['uri'])) {
                $interactUrlRaw = (string)$displayStatus['uri'];
            }
        }
        $canonicalUrl = htmlspecialchars($canonicalUrlRaw);
        $interactUrl = htmlspecialchars($interactUrlRaw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $apUrl = htmlspecialchars($activityPubUrlRaw !== '' ? $activityPubUrlRaw : $interactUrlRaw, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Format timestamp nicely
        $tsDate = date('j M Y', strtotime($s['created_at']));
        $tsTime = date('H:i', strtotime($s['created_at']));
        $tsFull = htmlspecialchars($tsDate . ' · ' . $tsTime);

        // Media grid (same style as profile page)
        $mediaGrid = '';
        $mc = count($mediaItems);
        if ($mc) {
            $items = '';
            foreach ($mediaItems as $m) {
                $mUrl = htmlspecialchars($m['url'] ?? '');
                $mAlt = htmlspecialchars($m['description'] ?? '');
                if (in_array($m['type'] ?? 'image', ['video', 'gifv'])) {
                    $items .= "<div class=\"media-item\"><video src=\"$mUrl\" controls preload=\"metadata\"></video></div>";
                } else {
                    $altBadge = !empty($m['description']) ? '<span class="alt-badge">ALT</span>' : '';
                    $items .= "<div class=\"media-item\"><a href=\"$mUrl\" target=\"_blank\" rel=\"noopener\"><img src=\"$mUrl\" alt=\"$mAlt\" loading=\"lazy\"></a>$altBadge</div>";
                }
            }
            $mediaGrid = '<div class="media-grid count-' . $mc . '">' . $items . '</div>';
        }
        $mediaSensitive = !empty($displayStatus['sensitive']) && $mc > 0;
        if ($mediaSensitive && $mediaGrid !== '') {
            $mediaGrid = '<button class="sensitive-overlay" onclick="this.nextElementSibling.style.display=\'\';this.remove()">Sensitive media — click to reveal</button>'
                . '<div style="display:none">' . $mediaGrid . '</div>';
        }
        $pollHtml = $this->renderPublicPoll($displayStatus['id'], 'status');
        $cardHtml = $this->renderPublicCard($displayStatus);
        $quoteHtml = $this->renderPublicQuote($displayStatus);
        $temporaryBadge = $this->renderTemporaryBadge((string)($displayStatus['expires_at'] ?? ''));
        $temporaryMeta = !empty($displayStatus['expires_at'])
            ? '<span>&middot;</span><span>Deletes ' . htmlspecialchars($this->formatPollExpiry((string)$displayStatus['expires_at']) ?? (string)$displayStatus['expires_at'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</span>'
            : '';

        // CW bar (same style as web client)
        $hasCw = (string)($displayStatus['cw'] ?? '') !== '';
        $cwHtml = $hasCw
            ? '<div class="cw-bar"><span>⚠ ' . htmlspecialchars($displayStatus['cw']) . '</span><button class="cw-toggle" onclick="toggleCWContent(this)">Show more</button></div>'
            : '';
        $cwContentStyle = $hasCw ? ' style="display:none"' : '';

        // Counts
        $rc = (int)($displayStatus['reply_count'] ?? 0);
        $reblogs = (int)($displayStatus['reblog_count'] ?? 0);
        $favs    = (int)($displayStatus['favourite_count'] ?? 0);
        $focalStats = '';
        if ($reblogs > 0 || $favs > 0) {
            $parts = [];
            if ($reblogs > 0) $parts[] = '<span><strong>' . $reblogs . '</strong> ' . ($reblogs === 1 ? 'repost' : 'reposts') . '</span>';
            if ($favs > 0)    $parts[] = '<span><strong>' . $favs . '</strong> ' . ($favs === 1 ? 'like' : 'likes') . '</span>';
            $focalStats = '<div class="focal-stats">' . implode('', $parts) . '</div>';
        }
        $rcHtml = $rc > 0 ? '<span class="action-count">' . $rc . '</span>' : '';
        $bcHtml = $reblogs > 0 ? '<span class="action-count">' . $reblogs . '</span>' : '';
        $fcHtml = $favs > 0 ? '<span class="action-count">' . $favs . '</span>' : '';

        $v = AP_VERSION;

        header('Content-Type: text/html; charset=utf-8');
        echo <<<HTML
<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$uname — Post</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text x=%2250%25%22 y=%2252%25%22 text-anchor=%22middle%22 dominant-baseline=%22middle%22 font-size=%2244%22 font-family=%22Arial,sans-serif%22>⋰⋱</text></svg>">
<meta name="description" content="$ogDesc">
<link rel="canonical" href="$canonicalUrl">
<meta property="og:type" content="article">
<meta property="og:url" content="$canonicalUrl">
<meta property="og:title" content="$uname">
<meta property="og:description" content="$ogDesc">
<meta property="og:image" content="$ogImage">
<meta property="og:site_name" content="$name">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="$uname">
<meta name="twitter:description" content="$ogDesc">
<meta name="twitter:image" content="$ogImage">
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

.col-main{max-width:600px;margin:0 auto;border-left:1px solid var(--border);border-right:1px solid var(--border);min-height:100vh;background:var(--surface)}

/* Back header — same as web client #col-header */
.back-header{
  display:flex;align-items:center;gap:.5rem;padding:.75rem 1rem;
  border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;
  background:color-mix(in srgb,var(--surface) 85%,transparent);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)
}
.back-btn{
  background:none;border:none;cursor:pointer;width:34px;height:34px;
  border-radius:50%;display:flex;align-items:center;justify-content:center;
  color:var(--text);transition:background .15s;text-decoration:none
}
.back-btn:hover{background:var(--hover);text-decoration:none}
.back-btn svg{width:1.2rem;height:1.2rem;fill:currentColor}
.back-title{font-weight:700;font-size:1.05rem}

/* Status card — focal view, same as web client .status-focal */
.status-card{padding:.75rem 1rem .6rem;background:var(--surface)}
.status-inner{display:flex;gap:.65rem}
.status-left{display:flex;flex-direction:column;align-items:center;gap:4px;position:relative}
.avatar{width:42px;height:42px;border-radius:50%;object-fit:cover;cursor:pointer;flex-shrink:0;display:block}
.avatar:hover{opacity:.85}
.status-body{flex:1;min-width:0}
.status-header{display:flex;align-items:baseline;gap:.25rem;flex-wrap:nowrap;margin-bottom:.35rem}
.temporary-badge{display:inline-flex;align-items:center;padding:.12rem .45rem;border-radius:9999px;border:1px solid color-mix(in srgb,var(--amber) 35%,var(--border));background:color-mix(in srgb,var(--amber) 12%,transparent);color:var(--text2);font-size:.72rem;font-weight:700;white-space:nowrap}
.s-name{font-weight:600;font-size:.9rem;white-space:nowrap;max-width:60%;overflow:hidden;text-overflow:ellipsis;color:var(--text);cursor:pointer}
.s-name:hover{text-decoration:underline}
.s-acct{font-size:.85rem;color:var(--text3);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vis-icon{font-size:.75rem;color:var(--text3);flex-shrink:0}

/* Reply indicator */
.reply-indicator{font-size:.82rem;color:var(--text3);margin-bottom:.25rem;display:flex;align-items:center;gap:.25rem}
.reply-indicator svg{width:.82rem;height:.82rem;fill:currentColor;flex-shrink:0}
.reply-to-name{color:var(--text2);text-decoration:none}
.reply-to-name:hover{color:var(--blue);text-decoration:underline}

/* Content — focal size */
.s-content{font-size:1.05rem;line-height:1.5;word-break:break-word;margin-bottom:.5rem}
.s-content a{color:var(--blue)}
.s-content a:hover{text-decoration:underline}
.s-content p{margin-bottom:.35rem}
.s-content p:last-child{margin-bottom:0}

/* CW */
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

/* Media grid */
.media-grid{
  display:grid;gap:2px;border-radius:10px;overflow:hidden;
  margin-bottom:.65rem;max-height:380px
}
.media-grid.count-1{grid-template-columns:1fr}
.media-grid.count-2{grid-template-columns:1fr 1fr}
.media-grid.count-3{grid-template-columns:1fr 1fr}
.media-grid.count-3 .media-item:first-child{grid-row:1/3}
.media-grid.count-4{grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr}
.media-item{overflow:hidden;background:var(--border);display:flex;align-items:center;justify-content:center;min-height:80px;position:relative}
.media-item img,.media-item video{width:100%;height:100%;object-fit:cover;display:block}
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

/* Focal meta — same as web client */
.focal-meta{
  display:flex;align-items:center;gap:.3rem;
  padding-top:.65rem;border-top:1px solid var(--border);
  margin-top:.65rem;font-size:.82rem;color:var(--text3)
}
.focal-meta a{color:var(--text3);font-size:.82rem}
.focal-meta a:hover{color:var(--blue)}

/* Focal stats — same as web client */
.focal-stats{display:flex;gap:1rem;padding:.5rem 0;font-size:.88rem;color:var(--text2)}
.focal-stats strong{color:var(--text);font-weight:700}

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

/* Interact modal */
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:100;align-items:center;justify-content:center}
.modal{background:var(--surface);border-radius:var(--radius);padding:2rem;max-width:380px;width:90%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.12)}
.modal h3{font-size:1.1rem;font-weight:800;margin-bottom:.5rem}
.modal p{color:var(--text2);font-size:.9rem;margin-bottom:1.2rem;line-height:1.5}
.handle-box{font-family:ui-monospace,"SF Mono",monospace;font-size:.9rem;font-weight:700;background:var(--blue-bg);color:var(--blue);padding:.65rem 1.1rem;border-radius:10px;margin-bottom:1.2rem;cursor:pointer;user-select:all;border:2px solid transparent;transition:border-color .15s;word-break:break-all}
.handle-box:hover{border-color:var(--blue)}
.modal-close{color:var(--text2);font-size:.85rem;cursor:pointer;background:none;border:none;margin-top:.75rem;text-decoration:underline}
.follow-btn{padding:.45rem 1.1rem;border-radius:9999px;font-weight:600;font-size:.85rem;cursor:pointer;transition:all .15s;border:none;background:var(--blue);color:#fff;font-family:inherit}
.follow-btn:hover{opacity:.8}

/* View profile link */
.profile-link{
  display:flex;align-items:center;gap:.4rem;padding:1rem 1.25rem;
  border-top:1px solid var(--border);font-size:.85rem;font-weight:600;color:var(--text2)
}
.profile-link:hover{color:var(--blue);text-decoration:underline}
.profile-link svg{width:1rem;height:1rem;fill:currentColor;flex-shrink:0}

/* Server footer */
.server-info{max-width:600px;margin:1.5rem auto 0;text-align:center;padding:.75rem 1rem}
.server-info-links{display:flex;justify-content:center;flex-wrap:wrap;gap:.4rem;margin-bottom:.4rem}
.chip{color:var(--text2);font-size:.78rem;border:1px solid var(--border);padding:.25rem .65rem;border-radius:9999px;background:var(--surface)}
.chip:hover{border-color:var(--blue);color:var(--blue);text-decoration:none}
.server-info-meta{font-size:.75rem;color:var(--text3)}

@media(max-width:600px){
  .col-main{border-left:none;border-right:none}
}
</style>
</head>
<body>
<div class="col-main">
  <div class="back-header">
    <a href="$ownerProfileUrl" class="back-btn">
      <svg viewBox="0 0 24 24"><path d="M7.414 13l5.043 5.04-1.414 1.42L3.586 12l7.457-7.46 1.414 1.42L7.414 11H21v2H7.414z"/></svg>
    </a>
    <span class="back-title">Post</span>
  </div>

  <div class="status-card">
    <div class="status-inner">
      <div class="status-left">
        <a href="$profileUrl"><img class="avatar" src="$avatar" alt="$uname"></a>
      </div>
        <div class="status-body">
        $boostHtml
        <div class="status-header">
          <a href="$profileUrl" class="s-name">$uname</a>
          <span class="s-acct">$acct</span>
          $temporaryBadge
        </div>
        $replyHtml
        $cwHtml
        <div class="cw-content"$cwContentStyle>
          <div class="s-content">$contentRaw</div>
          $mediaGrid
          $cardHtml
          $quoteHtml
          $pollHtml
        </div>
        <div class="focal-meta">
          <span>$tsFull</span>
          $metaVis
          $temporaryMeta
          <span>&middot;</span>
          <a href="$apUrl">ActivityPub</a>
        </div>
        $focalStats
        <div class="action-bar">
          <button class="action-btn reply-btn" onclick="showInteract()" title="Reply"><svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>$rcHtml</button>
          <button class="action-btn boost-btn" onclick="showInteract()" title="Repost"><svg viewBox="0 0 24 24"><path d="M17 1L21 5L17 9V6H7V12H5V6C5 4.9 5.9 4 7 4H17V1ZM7 23L3 19L7 15V18H17V12H19V18C19 19.1 18.1 20 17 20H7V23Z"/></svg>$bcHtml</button>
          <button class="action-btn fav-btn" onclick="showInteract()" title="Like"><svg viewBox="0 0 24 24"><path d="M16.5 3c-1.74 0-3.41.81-4.5 2.09C10.91 3.81 9.24 3 7.5 3 4.42 3 2 5.42 2 8.5c0 3.78 3.4 6.86 8.55 11.54L12 21.35l1.45-1.32C18.6 15.36 22 12.28 22 8.5 22 5.42 19.58 3 16.5 3zm-4.4 15.55l-.1.1-.1-.1C7.14 14.24 4 11.39 4 8.5 4 6.5 5.5 5 7.5 5c1.54 0 3.04.99 3.57 2.36h1.87C13.46 5.99 14.96 5 16.5 5c2 0 3.5 1.5 3.5 3.5 0 2.89-3.14 5.74-7.9 10.05z"/></svg>$fcHtml</button>
        </div>
      </div>
    </div>
  </div>

  <a href="$profileUrl" class="profile-link">
    <svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
    View $uname's profile
  </a>
</div>

<!-- Interact modal -->
<div class="modal-backdrop" id="interact-modal">
  <div class="modal">
    <h3>Interact with this post</h3>
    <p>Copy the post URL and paste it into the search field of your favourite Fediverse app to reply, repost, or like it.</p>
    <div class="handle-box" onclick="navigator.clipboard&&navigator.clipboard.writeText(this.innerText).then(()=>{this.style.borderColor='var(--green)'})">$interactUrl</div>
    <br>
    <button class="follow-btn" onclick="window.open('https://joinmastodon.org/apps','_blank','noopener,noreferrer')">Get a Fediverse app</button>
    <br>
    <button class="modal-close" onclick="document.getElementById('interact-modal').style.display='none'">Close</button>
  </div>
</div>

<div class="server-info">
  <div class="server-info-links">
    <a href="/api/v1/instance" class="chip">API</a>
    <a href="/.well-known/nodeinfo" class="chip">NodeInfo</a>
    <a href="/about" class="chip">About</a>
  </div>
  <div class="server-info-meta">$domain &bull; v$v</div>
</div>
<script>
document.getElementById('interact-modal').addEventListener('click',function(e){if(e.target===this)this.style.display='none'});
function showInteract(){document.getElementById('interact-modal').style.display='flex'}
function togglePollResults(id, btn){
  var el = document.getElementById(id);
  if (!el) return;
  var open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  if (btn) btn.textContent = open ? 'View results' : 'Hide results';
}
function toggleCWContent(btn){
  var wrap = btn.closest('.cw-bar')?.nextElementSibling;
  if (!wrap) return;
  var open = wrap.style.display !== 'none';
  wrap.style.display = open ? 'none' : 'block';
  btn.textContent = open ? 'Show more' : 'Show less';
}
</script>
</body></html>
HTML;
        exit;
    }

    public function about(array $p): void
    {
        $name   = htmlspecialchars(AP_NAME);
        $desc   = htmlspecialchars(AP_DESCRIPTION);
        $domain = htmlspecialchars(AP_DOMAIN);
        $version = htmlspecialchars(AP_VERSION);
        $software = htmlspecialchars(AP_SOFTWARE);
        $adminEmail = htmlspecialchars(AP_ADMIN_EMAIL);
        $baseUrl = htmlspecialchars(AP_BASE_URL);
        $sourceUrl = htmlspecialchars((string)AP_SOURCE_URL);
        $openReg = AP_OPEN_REG ? 'Open' : 'Closed';
        $registerLink = AP_OPEN_REG ? '<a class="cta primary" href="/web/register">Create account</a>' : '';
        $sourceLink = $sourceUrl !== '' ? '<a href="' . $sourceUrl . '" target="_blank" rel="noopener">Source code</a>' : '';
        header('Content-Type: text/html; charset=utf-8');
        echo "<!DOCTYPE html><html lang=\"en\"><head><meta charset=utf-8><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>About – $name</title>"
           . "<link rel=\"icon\" href=\"data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text x=%2250%25%22 y=%2252%25%22 text-anchor=%22middle%22 dominant-baseline=%22middle%22 font-size=%2244%22 font-family=%22Arial,sans-serif%22>⋰⋱</text></svg>\">"
           . "<style>:root{--blue:#0085FF;--blue-bg:#E0EDFF;--text:#0F1419;--text2:#66788A;--text3:#8D99A5;--bg:#fff;--surface:#F3F3F8;--border:#E5E7EB}@media(prefers-color-scheme:dark){:root{--text:#F1F3F5;--text2:#7B8794;--text3:#545864;--bg:#0A0E14;--surface:#161823;--border:#2E3039;--blue-bg:#0C1B3A}}*{box-sizing:border-box}body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;max-width:860px;margin:0 auto;padding:2.25rem 1rem 3rem;background:var(--bg);color:var(--text);line-height:1.6}a{color:var(--blue)}.back{display:inline-flex;align-items:center;gap:.4rem;margin-bottom:1.25rem;color:var(--text2);text-decoration:none}.hero{margin-bottom:1.6rem}.eyebrow{display:inline-flex;align-items:center;gap:.45rem;background:var(--blue-bg);color:var(--blue);font-weight:800;font-size:.8rem;padding:.38rem .8rem;border-radius:999px;margin-bottom:.9rem}.hero h1{font-size:2rem;line-height:1.1;margin:0 0 .7rem}.hero p{margin:0;color:var(--text2);max-width:720px}.cta-row{display:flex;gap:.7rem;flex-wrap:wrap;margin-top:1.1rem}.cta{display:inline-flex;align-items:center;justify-content:center;padding:.65rem 1rem;border-radius:999px;border:1px solid var(--border);text-decoration:none;font-weight:700;color:var(--text)}.cta.primary{background:var(--blue);border-color:var(--blue);color:#fff}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin:1.5rem 0}.card,.section{background:var(--surface);border:1px solid var(--border);border-radius:18px}.card{padding:1rem 1.1rem}.card h2{font-size:1rem;margin:0 0 .45rem}.card p{margin:0;color:var(--text2);font-size:.95rem}.card .facts{margin-top:.2rem}.card .facts dt,.card .facts dd,.card ul{font-size:.92rem}.section{padding:1.15rem 1.2rem;margin-top:1rem}.section h2{font-size:1rem;margin:0 0 .65rem}.facts{display:grid;grid-template-columns:max-content 1fr;gap:.45rem .9rem;font-size:.95rem}.facts dt{color:var(--text3)}.facts dd{margin:0;word-break:break-word}.chips{display:flex;gap:.55rem;flex-wrap:wrap}.chip{display:inline-flex;align-items:center;padding:.45rem .75rem;border-radius:999px;background:var(--bg);border:1px solid var(--border);font-size:.9rem;color:var(--text2)}ul{margin:.4rem 0 0 1.1rem;color:var(--text2)}li+li{margin-top:.32rem}</style></head>"
           . "<body>"
           . "<a class=\"back\" href=\"/\">&larr; Back</a>"
           . "<div class=\"hero\">"
           . "<div class=\"eyebrow\"><span>⋰⋱</span><span>About Starling</span></div>"
           . "<h1>$name</h1>"
           . "<p>$desc</p>"
           . "<div class=\"cta-row\"><a class=\"cta\" href=\"/web/login\">Log in</a>$registerLink<a class=\"cta\" href=\"/users/\">Browse profiles</a></div>"
           . "</div>"
           . "<div class=\"grid\">"
           . "<div class=\"card\"><h2>What this is</h2><p>$name is an ActivityPub server. It can exchange posts, follows, profiles, replies, likes, and boosts with other software across the fediverse.</p></div>"
           . "<div class=\"card\"><h2>Compatible platforms</h2><p>Mastodon, Misskey, Pleroma, GoToSocial, PixelFed, and other ActivityPub-compatible platforms can interact with this server.</p></div>"
           . "<div class=\"card\"><h2>Lightweight by design</h2><p>Starling is deliberately lightweight: pure PHP, no heavy external dependencies, and designed to run comfortably on small VPS hosts and typical shared hosting environments.</p></div>"
           . "<div class=\"card\"><h2>Starling idea</h2><p>Inspired by starling murmurations: decentralized, leaderless, and shaped by nearby connection.</p></div>"
           . "<div class=\"card\"><h2>Instance details</h2><dl class=\"facts\">"
           . "<dt>Domain</dt><dd>$domain</dd>"
           . "<dt>Base URL</dt><dd>$baseUrl</dd>"
           . "<dt>Registrations</dt><dd>$openReg</dd>"
           . "<dt>Software</dt><dd>$software</dd>"
           . "<dt>Version</dt><dd>$version</dd>"
           . "<dt>Admin</dt><dd><a href=\"mailto:$adminEmail\">$adminEmail</a></dd>"
           . ($sourceUrl !== '' ? "<dt>Source</dt><dd>$sourceLink</dd>" : '')
           . "</dl></div>"
           . "<div class=\"card\"><h2>What you can do here</h2><ul><li>Publish posts and replies.</li><li>Follow accounts here and across the fediverse.</li><li>Use Mastodon-compatible clients and web apps.</li><li>Interact with likes, boosts, bookmarks, lists, filters, and profile metadata.</li></ul></div>"
           . "</div>"
           . "<div class=\"section\"><h2>Useful links</h2><div class=\"chips\"><a class=\"chip\" href=\"/\">Home</a><a class=\"chip\" href=\"/users/\">Profiles</a><a class=\"chip\" href=\"/web/login\">Web app</a><a class=\"chip\" href=\"/privacy\">Privacy</a><a class=\"chip\" href=\"/terms\">Terms</a><a class=\"chip\" href=\"/rules\">Rules</a></div></div>"
           . "<p style=\"margin-top:1.2rem;color:var(--text3);font-size:.92rem\">An idea by <a href=\"https://dfaria.eu\" target=\"_blank\" rel=\"noopener\">Domingos Faria</a>.</p>"
           . "</body></html>";
        exit;
    }

    private function publicContentPage(string $title, string $body): never
    {
        $pageTitle = htmlspecialchars($title, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $bodyHtml = trim($body) !== ''
            ? nl2br(htmlspecialchars($body, ENT_QUOTES | ENT_HTML5, 'UTF-8'))
            : '<p style="color:var(--text2)">This page has not been configured yet.</p>';
        header('Content-Type: text/html; charset=utf-8');
        echo "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{$pageTitle} - " . htmlspecialchars(AP_NAME, ENT_QUOTES | ENT_HTML5, 'UTF-8') . "</title>"
            . "<link rel=\"icon\" href=\"data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text x=%2250%25%22 y=%2252%25%22 text-anchor=%22middle%22 dominant-baseline=%22middle%22 font-size=%2244%22 font-family=%22Arial,sans-serif%22>⋰⋱</text></svg>\"><style>:root{--blue:#0085FF;--text:#0F1419;--text2:#66788A;--bg:#fff;--surface:#F3F3F8;--border:#E5E7EB}@media(prefers-color-scheme:dark){:root{--text:#F1F3F5;--text2:#7B8794;--bg:#0A0E14;--surface:#161823;--border:#2E3039}}body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;max-width:760px;margin:3rem auto;padding:1rem;background:var(--bg);color:var(--text)}article{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1.4rem 1.5rem;line-height:1.7}h1{margin-bottom:1rem}p{margin-bottom:1rem}a{color:var(--blue)}</style></head>"
            . "<body><h1>{$pageTitle}</h1><article>{$bodyHtml}</article><p><a href=\"/\">&larr; Back</a></p></body></html>";
        exit;
    }

    public function privacy(array $p): void
    {
        $page = AdminModel::instanceContent('privacy');
        $this->publicContentPage($page['title'] ?? 'Privacy policy', $page['body'] ?? '');
    }

    public function terms(array $p): void
    {
        $page = AdminModel::instanceContent('terms');
        $this->publicContentPage($page['title'] ?? 'Terms of service', $page['body'] ?? '');
    }

    public function rules(array $p): void
    {
        $rules = AdminModel::instanceRules();
        $body = '';
        foreach ($rules as $index => $rule) {
            $body .= ($index + 1) . '. ' . $rule['text'] . "\n\n";
        }
        $this->publicContentPage('Server rules', trim($body));
    }

    public function install(array $p): void
    {
        // If users already exist, redirect home
        if (DB::count('users') > 0) {
            header('Location: /'); exit;
        }
        if (!$this->installEnabled()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Install disabled</title></head><body><h1>Installer disabled</h1><p>Enable it explicitly before first setup.</p></body></html>';
            exit;
        }
        $this->startInstallSession();
        $_SESSION['install_csrf'] = bin2hex(random_bytes(16));
        $this->renderInstallForm();
    }

    public function installPost(array $p): void
    {
        if (DB::count('users') > 0) {
            header('Location: /'); exit;
        }
        if (!$this->installEnabled()) {
            http_response_code(403);
            exit;
        }
        $this->startInstallSession();
        $csrf = (string)($_POST['csrf'] ?? '');
        if (!$csrf || !hash_equals($_SESSION['install_csrf'] ?? '', $csrf)) {
            $this->renderInstallForm('Invalid request.');
            return;
        }
        $_SESSION['install_csrf'] = bin2hex(random_bytes(16));

        $siteName    = trim($_POST['site_name'] ?? '');
        $baseUrlRaw  = trim($_POST['base_url'] ?? '');
        $adminEmail  = trim($_POST['admin_email'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $username    = trim($_POST['username'] ?? '');
        $email       = trim($_POST['email'] ?? '');
        $password    = $_POST['password'] ?? '';

        $siteName = $siteName !== '' ? $siteName : 'Starling';
        $baseUrl = rtrim($baseUrlRaw, '/');
        $scheme = (string)parse_url($baseUrl, PHP_URL_SCHEME);
        $domain = (string)parse_url($baseUrl, PHP_URL_HOST);
        $path   = (string)parse_url($baseUrl, PHP_URL_PATH);

        $error = '';
        if (!$siteName || !$baseUrl || !$adminEmail || !$username || !$email || !$password) {
            $error = 'All fields are required.';
        } elseif (!filter_var($baseUrl, FILTER_VALIDATE_URL) || !in_array($scheme, ['http', 'https'], true) || $domain === '') {
            $error = 'Base URL must be a valid http:// or https:// URL.';
        } elseif ($path !== '' && $path !== '/') {
            $error = 'Base URL must not include a path.';
        } elseif (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid administrator email address.';
        } elseif (!preg_match('/^\w{1,30}$/', $username)) {
            $error = 'Invalid username (letters, numbers, underscore, max. 30 characters).';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif (strlen($password) < 8) {
            $error = 'Password must be at least 8 characters long.';
        }

        if ($error) {
            $this->renderInstallForm($error); return;
        }

        $description = $description !== '' ? $description : $siteName . ' is an ActivityPub server.';
        $this->writeGeneratedConfig([
            'installed'     => true,
            'domain'        => strtolower($domain),
            'name'          => $siteName,
            'description'   => $description,
            'admin_email'   => $adminEmail,
            'base_url'      => $baseUrl,
            'db_path'       => ROOT . '/storage/db/activitypub.sqlite',
            'media_dir'     => ROOT . '/storage/media',
            'max_upload_mb' => AP_MAX_UPLOAD_MB,
            'open_reg'      => AP_OPEN_REG,
            'post_chars'    => AP_POST_CHARS,
            'debug'         => AP_DEBUG,
            'version'       => AP_VERSION,
            'software'      => AP_SOFTWARE,
            'source_url'    => AP_SOURCE_URL,
            'atproto_did'   => '',
        ]);

        UserModel::create([
            'username' => $username,
            'email'    => $email,
            'password' => $password,
            'is_admin' => 1,
        ]);
        $allowInstallFlag = ROOT . '/storage/.allow-install';
        if (is_file($allowInstallFlag)) {
            @unlink($allowInstallFlag);
        }

        header('Content-Type: text/html; charset=utf-8');
        $uSafe  = htmlspecialchars($username);
        $domainSafe = htmlspecialchars(strtolower($domain), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        echo <<<HTML
<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8"><title>Installed!</title>
<style>:root{--bg:#fff;--surface:#fff;--blue:#0085FF;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--green:#20BC07;--green-bg:#E0F8DC}
@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--green-bg:#0C2A0A}}
body{font-family:'Inter',system-ui,sans-serif;max-width:500px;margin:3rem auto;padding:1rem;background:var(--bg);color:var(--text)}
.card{background:var(--surface);border:1px solid var(--border);padding:2rem;border-radius:12px;text-align:center}
h2{color:var(--green);margin-bottom:1rem} a{color:var(--blue)}</style>
</head><body>
<div class="card">
  <h2>✓ Server installed!</h2>
  <p>Account <strong>$uSafe</strong> created.</p>
  <p style="margin-top:1rem">Connect your Mastodon-compatible client to <strong>$domainSafe</strong><br>
  and sign in with your username and password.</p>
  <p style="margin-top:1.5rem"><a href="/">← Home page</a></p>
</div></body></html>
HTML;
        exit;
    }

    private function renderInstallForm(string $error = ''): void
    {
        $err  = $error ? '<p class="err">' . htmlspecialchars($error) . '</p>' : '';
        $allowInstall = defined('AP_ALLOW_INSTALL') ? (bool)AP_ALLOW_INSTALL : false;
        $detectedBaseUrl = request_base_url();
        $defaultName = htmlspecialchars(AP_NAME !== 'Starling' || !$allowInstall ? AP_NAME : 'Starling');
        $defaultBaseUrl = htmlspecialchars(AP_BASE_URL !== 'https://example.com' || !$allowInstall ? AP_BASE_URL : $detectedBaseUrl, ENT_QUOTES);
        $defaultAdminEmail = htmlspecialchars(AP_ADMIN_EMAIL !== 'admin@example.com' || !$allowInstall ? AP_ADMIN_EMAIL : 'admin@example.com', ENT_QUOTES);
        $defaultDescription = htmlspecialchars(AP_DESCRIPTION !== 'A lightweight ActivityPub server.' || !$allowInstall ? AP_DESCRIPTION : '', ENT_QUOTES);
        $csrf = htmlspecialchars($_SESSION['install_csrf'] ?? '', ENT_QUOTES);
        header('Content-Type: text/html; charset=utf-8');
        echo <<<HTML
<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Install – Starling</title>
<style>
:root{--bg:#fff;--surface:#fff;--blue:#0085FF;--blue2:#0070E0;--blue-bg:#E0EDFF;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--red:#EC4040}
@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--blue-bg:#0C1B3A}}
body{font-family:'Inter',system-ui,sans-serif;max-width:460px;margin:3rem auto;padding:1rem;background:var(--bg);color:var(--text)}
.card{background:var(--surface);border:1px solid var(--border);padding:2rem;border-radius:12px}
h2{margin:0 0 1rem;color:var(--blue)} label{display:block;margin:.8rem 0 .2rem;font-size:.9rem;color:var(--text2)}
input,textarea{width:100%;padding:.65rem;background:var(--surface);border:1px solid var(--border);border-radius:14px;color:var(--text);font-size:1rem;font-family:inherit}
textarea{resize:vertical;min-height:92px}
input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-bg)}
button{width:100%;margin-top:1.2rem;padding:.8rem;background:var(--blue);color:#fff;border:0;border-radius:9999px;cursor:pointer;font-size:1rem;font-weight:700;font-family:inherit;transition:background .15s}
button:hover{background:var(--blue2)}
.err{color:var(--red);background:color-mix(in srgb,var(--red) 8%,var(--surface));padding:.6rem;border-radius:6px;margin-bottom:1rem;font-size:.9rem}
.sub{color:var(--text2);margin-bottom:1rem;font-size:.9rem}
</style></head><body>
<div class="card">
  <h2>Install server</h2>
  <p class="sub">Configure the server and create the first administrator account.</p>
  $err
  <form method="POST" action="/install">
    <input type="hidden" name="csrf" value="$csrf">
    <label>Site name</label>
    <input name="site_name" value="$defaultName" placeholder="Starling" required autofocus>
    <label>Base URL</label>
    <input name="base_url" type="url" value="$defaultBaseUrl" placeholder="https://example.com" required>
    <label>Administrator email</label>
    <input name="admin_email" type="email" value="$defaultAdminEmail" placeholder="admin@example.com" required>
    <label>Description</label>
    <textarea name="description" placeholder="Optional">$defaultDescription</textarea>
    <label>Username</label>
    <input name="username" placeholder="admin" required>
    <label>Email</label>
    <input name="email" type="email" placeholder="admin@example.com" required>
    <label>Password (min. 8 characters)</label>
    <input name="password" type="password" required>
    <button type="submit">Install</button>
  </form>
</div></body></html>
HTML;
        exit;
    }
}
