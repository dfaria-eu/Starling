<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Models\{DB, OAuthModel, UserModel};

class WebClientCtrl
{
    // ── Auth (persistent cookie — survives browser restarts) ──────────────────

    private const COOKIE_NAME = 'ap_auth';
    private const COOKIE_TTL  = 365 * 24 * 3600; // 1 year

    private function setAuthCookie(string $token): void
    {
        setcookie(self::COOKIE_NAME, $token, [
            'expires'  => time() + self::COOKIE_TTL,
            'path'     => '/',
            'secure'   => is_https_request(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private function clearAuthCookie(): void
    {
        setcookie(self::COOKIE_NAME, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => is_https_request(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private function requireAuth(): array
    {
        $token = $_COOKIE[self::COOKIE_NAME] ?? '';
        if (!$token) $this->redirect('/web/login');

        $user = OAuthModel::userByToken($token);
        if (!$user) {
            $this->clearAuthCookie();
            $this->redirect('/web/login');
        }

        // Refresh cookie TTL on each visit so active users never get logged out
        $this->setAuthCookie($token);
        return [$user, $token];
    }

    // Sessions used only for CSRF on the login form
    private function startSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_name('ap_csrf');
            session_set_cookie_params(['path' => '/', 'secure' => is_https_request(), 'httponly' => true, 'samesite' => 'Lax']);
            session_start();
        }
        if (empty($_SESSION['web_csrf'])) {
            $_SESSION['web_csrf'] = bin2hex(random_bytes(16));
        }
    }

    private function ensureWebApp(): string
    {
        $app = DB::one("SELECT id FROM oauth_apps WHERE name='Web Client'");
        if ($app) return $app['id'];
        $app = OAuthModel::createApp([
            'client_name'   => 'Web Client',
            'website'       => 'https://' . AP_DOMAIN,
            'redirect_uris' => 'urn:ietf:wg:oauth:2.0:oob',
            'scopes'        => 'read write follow push',
        ]);
        return $app['id'];
    }

    // ── Brute-force protection ─────────────────────────────────────────────────

    private function checkRateLimit(string $ip): bool
    {
        try {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS web_login_attempts (ip TEXT NOT NULL, ts INTEGER NOT NULL)");
            $c = (int)(DB::one(
                "SELECT COUNT(*) c FROM web_login_attempts WHERE ip=? AND ts>?",
                [$ip, time() - 900]
            )['c'] ?? 0);
            return $c >= 10;
        } catch (\Throwable) { return false; }
    }

    private function recordFailedAttempt(string $ip): void
    {
        try {
            DB::run("INSERT INTO web_login_attempts (ip, ts) VALUES (?, ?)", [$ip, time()]);
            DB::run("DELETE FROM web_login_attempts WHERE ts<?", [time() - 7200]);
        } catch (\Throwable) {}
    }

    // ── Public routes ─────────────────────────────────────────────────────────

    public function login(array $p): void
    {
        // Already logged in?
        if (!empty($_COOKIE[self::COOKIE_NAME]) && OAuthModel::userByToken($_COOKIE[self::COOKIE_NAME])) {
            $this->redirect('/web');
        }

        $this->startSession();
        $error = '';
        $ip    = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $csrf = $_POST['csrf'] ?? '';
            if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) {
                $error = 'Invalid request.';
            } elseif ($this->checkRateLimit($ip)) {
                $error = 'Too many failed attempts. Please wait 15 minutes.';
            } else {
                $u = UserModel::verify($_POST['username'] ?? '', $_POST['password'] ?? '');
                if ($u && empty($u['is_suspended'])) {
                    $appId = $this->ensureWebApp();
                    $token = OAuthModel::createToken($appId, $u['id'], 'read write follow push');
                    $this->setAuthCookie($token);
                    session_destroy();
                    $this->redirect('/web');
                } else {
                    sleep(1);
                    $this->recordFailedAttempt($ip);
                    $error = 'Invalid credentials.';
                }
            }
        }
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
        $csrf = $_SESSION['csrf'];
        session_write_close();
        $this->html($this->loginPage($csrf, $error));
    }

    public function register(array $p): void
    {
        if (!AP_OPEN_REG) {
            $this->redirect('/web/login');
        }
        if (!empty($_COOKIE[self::COOKIE_NAME]) && OAuthModel::userByToken($_COOKIE[self::COOKIE_NAME])) {
            $this->redirect('/web');
        }

        $this->startSession();
        $error = '';

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $csrf = (string)($_POST['csrf'] ?? '');
            if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) {
                $error = 'Invalid request.';
            } else {
                $username = trim(strtolower((string)($_POST['username'] ?? '')));
                $email = trim(strtolower((string)($_POST['email'] ?? '')));
                $password = (string)($_POST['password'] ?? '');
                $passwordConfirm = (string)($_POST['password_confirm'] ?? '');

                if ($username === '' || $email === '' || $password === '') {
                    $error = 'Username, email, and password are required.';
                } elseif (!preg_match('/^\w{1,30}$/', $username)) {
                    $error = 'Invalid username.';
                } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $error = 'Invalid email address.';
                } elseif (strlen($password) < 8) {
                    $error = 'Password must be at least 8 characters long.';
                } elseif ($password !== $passwordConfirm) {
                    $error = 'Passwords do not match.';
                } elseif (UserModel::byUsernameAny($username)) {
                    $error = 'Username already taken.';
                } elseif (UserModel::byEmailAny($email)) {
                    $error = 'Email already registered.';
                } else {
                    $user = UserModel::create([
                        'username' => $username,
                        'email' => $email,
                        'password' => $password,
                    ]);
                    $appId = $this->ensureWebApp();
                    $token = OAuthModel::createToken($appId, $user['id'], 'read write follow push');
                    $this->setAuthCookie($token);
                    session_destroy();
                    $this->redirect('/web');
                }
            }
        }

        $_SESSION['csrf'] = bin2hex(random_bytes(16));
        $csrf = $_SESSION['csrf'];
        session_write_close();
        $this->html($this->registerPage($csrf, $error));
    }

    public function logout(array $p): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            $this->redirect('/web');
        }
        $this->startSession();
        $csrf = (string)($_POST['csrf'] ?? '');
        if (!$csrf || !hash_equals($_SESSION['web_csrf'] ?? '', $csrf)) {
            http_response_code(403);
            echo 'Invalid request.';
            exit;
        }
        $token = $_COOKIE[self::COOKIE_NAME] ?? '';
        if ($token) OAuthModel::revoke($token);
        $this->clearAuthCookie();
        $this->redirect('/web/login');
    }

    /**
     * SSO bridge: validates the web auth cookie, creates the admin PHP session,
     * and redirects to /admin — so admins don't need to log in again.
     */
    public function adminSso(array $p): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            $this->redirect('/web/settings');
        }
        $this->startSession();
        $csrf = (string)($_POST['csrf'] ?? '');
        if (!$csrf || !hash_equals($_SESSION['web_csrf'] ?? '', $csrf)) {
            http_response_code(403);
            echo 'Invalid request.';
            exit;
        }
        [$user] = $this->requireAuth();
        if (!$user['is_admin']) {
            http_response_code(403);
            echo 'Access denied.';
            exit;
        }
        // Close the web CSRF session before opening the dedicated admin session.
        // Otherwise PHP keeps using the current session name and the admin login
        // state gets written into the wrong cookie namespace.
        session_write_close();
        \App\Models\AdminModel::startSession();
        session_regenerate_id(true);
        $_SESSION['admin_user_id'] = $user['id'];
        $_SESSION['admin_ip']      = $_SERVER['REMOTE_ADDR'] ?? '';
        session_write_close();
        $this->redirect('/admin');
    }

    public function home(array $p): void
    {
        $this->renderShellView('HOME');
    }

    public function local(array $p): void
    {
        $this->renderShellView('LOCAL');
    }

    public function notifications(array $p): void
    {
        $this->renderShellView('NOTIFICATIONS');
    }

    public function thread(array $p): void
    {
        $this->renderShellView('THREAD', (string)$p['id']);
    }

    public function profile(array $p): void
    {
        $this->renderShellView('PROFILE', (string)$p['id']);
    }

    public function followers(array $p): void
    {
        $this->renderShellView('FOLLOWERS', (string)$p['id']);
    }

    public function following(array $p): void
    {
        $this->renderShellView('FOLLOWING', (string)$p['id']);
    }

    public function tagTimeline(array $p): void
    {
        $this->renderShellView('TAG_TIMELINE', urldecode((string)$p['id']));
    }

    public function search(array $p): void
    {
        $this->renderShellView('SEARCH');
    }

    public function favourites(array $p): void
    {
        $this->renderShellView('FAVOURITES');
    }

    public function bookmarks(array $p): void
    {
        $this->renderShellView('BOOKMARKS');
    }

    public function conversations(array $p): void
    {
        $this->renderShellView('CONVERSATIONS');
    }

    public function settings(array $p): void
    {
        $this->renderShellView('SETTINGS');
    }

    public function intentCompose(array $p): void
    {
        $text = substr(trim($_GET['text'] ?? ''), 0, AP_POST_CHARS);
        $this->renderShellView('HOME', null, $text ?: null);
    }

    public function explore(array $p): void
    {
        $this->renderShellView('EXPLORE');
    }

    public function lists(array $p): void
    {
        $this->renderShellView('LISTS');
    }

    public function listTimeline(array $p): void
    {
        $this->renderShellView('LIST_TIMELINE', (string)$p['id']);
    }

    public function editProfile(array $p): void
    {
        $this->renderShellView('EDIT_PROFILE');
    }

    private function renderShellView(string $view, ?string $viewId = null, ?string $composeText = null): void
    {
        [$user, $token] = $this->requireAuth();
        $this->html($this->shell($view, $viewId, $user, $token, $composeText));
    }

    // ── Output helpers ────────────────────────────────────────────────────────

    private function html(string $s): never
    {
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache');
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: base-uri 'self'; object-src 'none'; frame-ancestors 'self';");
        echo $s;
        exit;
    }

    private function redirect(string $url): never
    {
        header('Location: ' . $url);
        exit;
    }

    // ── Shell (SPA wrapper) ───────────────────────────────────────────────────

    private function shell(string $view, ?string $viewId, array $user, string $token, ?string $composeText = null): string
    {
        $this->startSession();
        $bootData = $this->shellBootData($view, $viewId, $user, $token, $composeText);
        $bootJson = json_encode($bootData, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
        $domain   = htmlspecialchars(AP_DOMAIN, ENT_QUOTES);
        $webCsrf  = htmlspecialchars((string)($_SESSION['web_csrf'] ?? ''), ENT_QUOTES);
        $navHtml  = $this->renderShellNavigation($this->shellNavLinks());

        return '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Starling App · ' . $domain . '</title>
<link rel="icon" href="' . htmlspecialchars(\site_favicon_url(), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>' . $this->css() . '</style>
</head>
<body>
<div id="ptr-indicator">↓ Pull to refresh</div>
<script>window.__WCFG__ = ' . $bootJson . ';</script>

<div id="app">
  <!-- Sidebar -->
  <nav id="sidebar">
    <a class="sidebar-logo" href="/web"><span class="fedi-symbol">⋰⋱</span><span>Starling</span></a>

    ' . $navHtml . '

    <button class="compose-btn" title="New post">
      <svg viewBox="0 0 24 24"><path d="M5 19h1.4l8.625-8.625-1.4-1.4L5 17.6V19ZM19.3 8.925l-4.25-4.2 1.4-1.4c.383-.383.846-.575 1.387-.575.542 0 1.005.192 1.388.575l1.4 1.4c.383.383.583.846.6 1.388.017.541-.175 1.004-.575 1.387l-1.35 1.425ZM4 21c-.283 0-.52-.096-.713-.288A.968.968 0 013 20v-2.825c0-.133.025-.258.075-.375s.125-.22.225-.325l10.6-10.6 4.25 4.25-10.6 10.6a.96.96 0 01-.325.225 1.032 1.032 0 01-.375.075H4Z"/></svg>
      <span>New post</span>
    </button>

    <div id="nav-user" onclick="toggleNavUserMenu(event)">
      <img id="nav-avatar" src="" alt="" width="36" height="36">
      <div style="min-width:0;flex:1">
        <div id="nav-name"></div>
        <div id="nav-acct"></div>
      </div>
      <svg viewBox="0 0 24 24" width="16" height="16" fill="var(--text3)" style="flex-shrink:0"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
    </div>

  </nav>

  <!-- Main column -->
  <main id="main-col">
    <div id="col-header">Home</div>
    <div id="home-tabs-bar" role="tablist" aria-label="Timelines"></div>
    <div id="col-content"></div>
  </main>

  <!-- Right panel (desktop only) -->
  <aside id="right-col">
    <div id="right-search-wrap">
      <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      <input type="search" id="right-search-input" placeholder="Search..." autocomplete="off">
    </div>
    <div id="right-trending"></div>
    <div style="padding:.75rem .5rem;font-size:.75rem;color:var(--text3)">Starling · ActivityPub</div>
  </aside>
</div>

<!-- Compose modal -->
<div id="compose-modal" role="dialog" aria-modal="true" aria-label="New post">
  <div id="compose-box">
    <div id="compose-header">
      <span id="compose-title">New post</span>
      <button onclick="Compose.close()" aria-label="Close">✕</button>
    </div>
    <div id="reply-preview" style="display:none"></div>
    <input id="cw-input" type="text" placeholder="Content warning (optional)" style="display:none">
    <div id="compose-body">
      <img id="compose-avatar" src="" alt="" width="38" height="38">
      <textarea id="compose-text" placeholder="What’s happening?" rows="4"></textarea>
    </div>
    <div id="compose-poll" style="display:none">
      <div id="compose-poll-options">
        <input class="compose-poll-option" type="text" placeholder="Option 1" maxlength="50">
        <input class="compose-poll-option" type="text" placeholder="Option 2" maxlength="50">
      </div>
      <div id="compose-poll-note" style="display:none"></div>
      <div id="compose-poll-controls">
        <button id="compose-poll-add" type="button">+ option</button>
        <label><input id="compose-poll-multiple" type="checkbox"> multiple choice</label>
        <select id="compose-poll-expiration">
          <option value="300">5 min</option>
          <option value="1800">30 min</option>
          <option value="3600">1 h</option>
          <option value="21600">6 h</option>
          <option value="86400" selected>1 day</option>
          <option value="259200">3 days</option>
          <option value="604800">7 days</option>
        </select>
      </div>
    </div>
    <div id="media-previews"></div>
    <div id="compose-toolbar">
      <div class="tool-btn">
        <label title="Add image/video">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>
          <input id="media-input" type="file" accept="image/*,video/*" multiple style="display:none">
        </label>
      </div>
      <button id="cw-toggle-btn" class="tool-btn" title="Content warning">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
      </button>
      <button id="poll-toggle-btn" class="tool-btn" title="Add poll">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M3 5h18v2H3V5zm0 6h12v2H3v-2zm0 6h8v2H3v-2zm14-5h4v7h-4v-7zm-6-4h4v11h-4V8z"/></svg>
      </button>
      <select id="vis-select" title="Visibility">
        <option value="public">🌐 Public</option>
        <option value="unlisted">🔒 Unlisted</option>
        <option value="private">👥 Followers only</option>
        <option value="direct">✉️ Direct</option>
      </select>
      <select id="expire-select" title="Auto-delete">
        <option value="">Keep permanently</option>
        <option value="3600">Delete after 1 hour</option>
        <option value="21600">Delete after 6 hours</option>
        <option value="86400">Delete after 1 day</option>
        <option value="604800">Delete after 7 days</option>
        <option value="2592000">Delete after 30 days</option>
      </select>
      <span id="char-count"></span>
      <button id="compose-submit" onclick="Compose.submit()">Post</button>
    </div>
  </div>
</div>

<!-- Lightbox -->
<div id="lightbox" role="dialog" aria-modal="true" aria-label="Image viewer">
  <button id="lb-close" aria-label="Close">✕</button>
  <img id="lb-img" src="" alt="">
</div>

<!-- Mobile bottom nav -->
<nav id="bottom-nav">
  <a class="bn-item" data-view="HOME" href="/web">
    <svg class="nav-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M12 3L4 10v10h5v-6h6v6h5V10L12 3zm0 2.84L18 11v7h-3v-6H9v6H6v-7l6-5.16z"/></svg>
    <svg class="nav-icon-active" viewBox="0 0 24 24" fill="currentColor"><path d="M12 3L4 10v10h5v-6h6v6h5V10L12 3z"/></svg>
    <span>Home</span>
  </a>
  <a class="bn-item" data-view="EXPLORE" href="/web/explore">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
    <span>Explore</span>
  </a>
  <a class="bn-item" data-view="NOTIFICATIONS" href="/web/notifications">
    <svg class="nav-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2zm-2 1H8v-6c0-2.48 1.51-4.5 4-4.5s4 2.02 4 4.5v6z"/></svg>
    <svg class="nav-icon-active" viewBox="0 0 24 24" fill="currentColor"><path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z"/></svg>
    <span>Notifications</span>
  </a>
  <button class="bn-item" id="bn-more" onclick="BottomSheet.toggle()">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 6h16v2H4zm0 5h16v2H4zm0 5h16v2H4z"/></svg>
    <span>More</span>
  </button>
</nav>

<!-- Mobile FAB compose button -->
<button id="mobile-fab" onclick="Compose.open()" aria-label="New post">
  <svg viewBox="0 0 24 24" fill="#fff"><path d="M5 19h1.4l8.625-8.625-1.4-1.4L5 17.6V19ZM19.3 8.925l-4.25-4.2 1.4-1.4c.383-.383.846-.575 1.387-.575.542 0 1.005.192 1.388.575l1.4 1.4c.383.383.583.846.6 1.388.017.541-.175 1.004-.575 1.387l-1.35 1.425ZM4 21c-.283 0-.52-.096-.713-.288A.968.968 0 013 20v-2.825c0-.133.025-.258.075-.375s.125-.22.225-.325l10.6-10.6 4.25 4.25-10.6 10.6a.96.96 0 01-.325.225 1.032 1.032 0 01-.375.075H4Z"/></svg>
</button>

<!-- Floating new posts pill -->
<button id="new-posts-pill" onclick="loadNewPosts()"></button>

<!-- Toast container -->
<div id="toast-container" aria-live="polite" aria-atomic="false"></div>

<!-- Bottom sheet overlay (mobile "More" menu) -->
<div id="bs-overlay" onclick="BottomSheet.close()"></div>
<div id="bottom-sheet">
  <div id="bs-handle"></div>
  <a class="bs-item" id="bn-profile" data-view="PROFILE" href="#">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
    <span>Profile</span>
  </a>
  <a class="bs-item" data-view="CONVERSATIONS" href="/web/conversations">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>
    <span>Conversations</span>
  </a>
  <div class="bs-divider"></div>
  <a class="bs-item" data-view="FAVOURITES" href="/web/favourites">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16.5 3c-1.74 0-3.41.81-4.5 2.09C10.91 3.81 9.24 3 7.5 3 4.42 3 2 5.42 2 8.5c0 3.78 3.4 6.86 8.55 11.54L12 21.35l1.45-1.32C18.6 15.36 22 12.28 22 8.5 22 5.42 19.58 3 16.5 3zm-4.4 15.55l-.1.1-.1-.1C7.14 14.24 4 11.39 4 8.5 4 6.5 5.5 5 7.5 5c1.54 0 3.04.99 3.57 2.36h1.87C13.46 5.99 14.96 5 16.5 5c2 0 3.5 1.5 3.5 3.5 0 2.89-3.14 5.74-7.9 10.05z"/></svg>
    <span>Favorites</span>
  </a>
  <a class="bs-item" data-view="BOOKMARKS" href="/web/bookmarks">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 3H7c-1.1 0-1.99.9-1.99 2L5 21l7-3 7 3V5c0-1.1-.9-2-2-2zm0 15l-5-2.18L7 18V5h10v13z"/></svg>
    <span>Bookmarks</span>
  </a>
  <a class="bs-item" data-view="LISTS" href="/web/lists">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg>
    <span>Lists</span>
  </a>
  <a class="bs-item" data-view="EDIT_PROFILE" href="/web/edit-profile">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
    <span>Edit profile</span>
  </a>
  <a class="bs-item" data-view="SETTINGS" href="/web/settings">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.14 12.94c.04-.3.06-.61.06-.94s-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
    <span>Settings</span>
  </a>
  <div class="bs-divider"></div>
  <form method="post" action="/web/logout" style="margin:0">
    <input type="hidden" name="csrf" value="' . $webCsrf . '">
    <button type="submit" class="bs-item bs-logout" style="width:100%">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/></svg>
      <span>Sign out</span>
    </button>
  </form>
</div>

<script>' . $this->js() . '</script>
</body>
</html>';
    }

    private function shellBootData(string $view, ?string $viewId, array $user, string $token, ?string $composeText = null): array
    {
        return [
            'token'         => $token,
            'domain'        => AP_DOMAIN,
            'myId'          => $user['id'],
            'myUsername'    => $user['username'],
            'myDisplayName' => $user['display_name'] ?: $user['username'],
            'myAvatar'      => local_media_url_or_fallback($user['avatar'] ?? '', '/img/avatar.svg'),
            'isAdmin'       => (bool)$user['is_admin'],
            'webCsrf'       => $_SESSION['web_csrf'] ?? '',
            'postChars'     => AP_POST_CHARS,
            'view'          => $view,
            'viewId'        => $viewId,
            'composeText'   => $composeText,
        ];
    }

    private function shellNavLinks(): array
    {
        return [
            ['view' => 'HOME',          'label' => 'Home',
             'icon'  => '<path d="M12 3L4 10v10h5v-6h6v6h5V10L12 3zm0 2.84L18 11v7h-3v-6H9v6H6v-7l6-5.16z"/>',
             'iconA' => '<path d="M12 3L4 10v10h5v-6h6v6h5V10L12 3z"/>'],
            ['view' => 'EXPLORE',       'label' => 'Explore',
             'icon'  => '<path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>',
             'iconA' => '<path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>'],
            ['view' => 'NOTIFICATIONS', 'label' => 'Notifications',
             'icon'  => '<path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2zm-2 1H8v-6c0-2.48 1.51-4.5 4-4.5s4 2.02 4 4.5v6z"/>',
             'iconA' => '<path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z"/>'],
            ['view' => 'CONVERSATIONS', 'label' => 'Conversations',
             'icon'  => '<path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/>',
             'iconA' => '<path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/>'],
            ['view' => 'LISTS',         'label' => 'Lists',
             'icon'  => '<path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/>',
             'iconA' => '<path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/>'],
            ['view' => 'PROFILE',       'label' => 'Profile',
             'icon'  => '<path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>',
             'iconA' => '<path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>'],
            ['view' => 'SETTINGS',      'label' => 'Settings',
             'icon'  => '<path d="M19.14 12.94c.04-.3.06-.61.06-.94s-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>',
             'iconA' => '<path d="M19.14 12.94c.04-.3.06-.61.06-.94s-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>'],
        ];
    }

    private function renderShellNavigation(array $navLinks): string
    {
        $navHtml = '';
        foreach ($navLinks as $nl) {
            $dataView  = htmlspecialchars($nl['view'], ENT_QUOTES);
            $label     = htmlspecialchars($nl['label'], ENT_QUOTES);
            $navHtml  .= '<a class="nav-link" data-view="' . $dataView . '" href="#" title="' . $label . '">'
                       . '<svg class="nav-icon" viewBox="0 0 24 24">' . $nl['icon'] . '</svg>'
                       . '<svg class="nav-icon-active" viewBox="0 0 24 24">' . ($nl['iconA'] ?? $nl['icon']) . '</svg>'
                       . '<span>' . $label . '</span>'
                       . '</a>' . "\n";
        }
        return $navHtml;
    }

    // ── Login page ────────────────────────────────────────────────────────────

    private function loginPage(string $csrf, string $error): string
    {
        $domain   = htmlspecialchars(AP_DOMAIN, ENT_QUOTES);
        $csrfHtml = htmlspecialchars($csrf, ENT_QUOTES);
        $errorHtml = '';
        $signupCta = AP_OPEN_REG
            ? '<div class="login-foot">No account yet? <a href="/web/register">Create account</a></div>'
            : '<div class="login-foot"><a href="/">Back to Starling</a></div>';
        if ($error !== '') {
            $errorHtml = '<div class="login-error">' . htmlspecialchars($error, ENT_QUOTES) . '</div>';
        }

        return '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In · ' . $domain . '</title>
<link rel="icon" href="' . htmlspecialchars(\site_favicon_url(), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">
<style>' . $this->css() . '</style>
</head>
<body>
<nav id="sidebar" style="width:auto;position:static;border:none;background:transparent;padding:1rem 1.5rem 0;flex-direction:row;height:auto;gap:.5rem;display:flex;align-items:center">
  <span class="sidebar-logo" style="margin-bottom:0"><span class="fedi-symbol">⋰⋱</span><span>Starling</span></span>
</nav>
<div class="login-wrap">
  <div class="login-card">
    <div class="login-title">Sign in</div>
    ' . $errorHtml . '
    <form method="post" action="/web/login" autocomplete="on">
      <input type="hidden" name="csrf" value="' . $csrfHtml . '">
      <div class="login-field">
        <label for="username">Username</label>
        <input id="username" type="text" name="username" autocomplete="username" required autofocus>
      </div>
      <div class="login-field">
        <label for="password">Password</label>
        <input id="password" type="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="login-submit">Sign In</button>
    </form>
    ' . $signupCta . '
  </div>
</div>
</body>
</html>';
    }

    private function registerPage(string $csrf, string $error): string
    {
        $domain   = htmlspecialchars(AP_DOMAIN, ENT_QUOTES);
        $csrfHtml = htmlspecialchars($csrf, ENT_QUOTES);
        $errorHtml = $error !== ''
            ? '<div class="login-error">' . htmlspecialchars($error, ENT_QUOTES) . '</div>'
            : '';

        return '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Create Account · ' . $domain . '</title>
<link rel="icon" href="' . htmlspecialchars(\site_favicon_url(), ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">
<style>' . $this->css() . '</style>
</head>
<body>
<nav id="sidebar" style="width:auto;position:static;border:none;background:transparent;padding:1rem 1.5rem 0;flex-direction:row;height:auto;gap:.5rem;display:flex;align-items:center;justify-content:space-between">
  <a class="sidebar-logo" href="/" style="margin-bottom:0"><span class="fedi-symbol">⋰⋱</span><span>Starling</span></a>
  <a class="login-alt-link" href="/web/login">Sign in</a>
</nav>
<div class="login-wrap">
  <div class="login-card">
    <div class="login-title">Create account</div>
    ' . $errorHtml . '
    <form method="post" action="/web/register" autocomplete="on">
      <input type="hidden" name="csrf" value="' . $csrfHtml . '">
      <div class="login-field">
        <label for="username">Username</label>
        <input id="username" type="text" name="username" autocomplete="username" required autofocus>
      </div>
      <div class="login-field">
        <label for="email">Email</label>
        <input id="email" type="email" name="email" autocomplete="email" required>
      </div>
      <div class="login-field">
        <label for="password">Password</label>
        <input id="password" type="password" name="password" autocomplete="new-password" minlength="8" required>
      </div>
      <div class="login-field">
        <label for="password_confirm">Confirm password</label>
        <input id="password_confirm" type="password" name="password_confirm" autocomplete="new-password" minlength="8" required>
      </div>
      <button type="submit" class="login-submit">Create account</button>
    </form>
    <div class="login-foot">Already have an account? <a href="/web/login">Sign in</a></div>
  </div>
</div>
</body>
</html>';
    }

    // ── CSS ───────────────────────────────────────────────────────────────────

    private function css(): string
    {
        return <<<'CSS'
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#fff;--surface:#fff;--hover:#F3F3F8;--blue:#0085FF;--blue2:#0070E0;--blue-bg:#E0EDFF;
  --border:#E5E7EB;--text:#0F1419;--text2:#66788A;--text3:#8D99A5;
  --green:#20BC07;--red:#EC4040;--pink:#EC4899;--amber:#FFC404;
  --sidebar-w:240px;--max-w:600px;--right-w:280px;--radius:12px;
}
@media(prefers-color-scheme:dark){
  :root{
    --bg:#0A0E14;--surface:#161823;--hover:#1E2030;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--text3:#545864;--blue-bg:#0C1B3A;
    --green:#4ade80;--red:#f87171;--pink:#f472b6;--amber:#fbbf24
  }
}
body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh;font-size:calc(16px * var(--ui-font-scale,1))}
html[data-theme-pref="light"]{color-scheme:light}
html[data-theme-pref="dark"]{color-scheme:dark}
html[data-theme-pref="light"]{
  --bg:#fff;--surface:#fff;--hover:#F3F3F8;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--text3:#8D99A5;--blue-bg:#E0EDFF;
  --green:#20BC07;--red:#EC4040;--pink:#EC4899;--amber:#FFC404;
}
html[data-theme-pref="dark"]{
  --bg:#0A0E14;--surface:#161823;--hover:#1E2030;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--text3:#545864;--blue-bg:#0C1B3A;
  --green:#4ade80;--red:#f87171;--pink:#f472b6;--amber:#fbbf24;
}
a{color:inherit;text-decoration:none}
img{max-width:100%}
button{font-family:inherit}

/* Layout */
#app{
  display:flex;min-height:100vh;
  max-width:calc(var(--sidebar-w) + var(--max-w) + var(--right-w));
  margin:0 auto;
}
#sidebar{
  position:sticky;top:0;height:100vh;height:100svh;width:var(--sidebar-w);flex-shrink:0;
  padding:.65rem 1rem;display:flex;flex-direction:column;gap:.1rem;
  background:transparent;
  overflow-y:auto;align-self:flex-start
}
.sidebar-logo{
  font-size:1.2rem;font-weight:800;padding:.7rem .85rem;color:var(--text);
  display:flex;align-items:center;gap:.5rem;margin-bottom:.35rem
}
.fedi-symbol{font-size:1.6rem;line-height:1;flex-shrink:0;color:var(--blue)}
.sidebar-logo span{color:var(--blue)}
.nav-link{
  display:flex;align-items:center;gap:.65rem;padding:.7rem .85rem;
  border-radius:9999px;color:var(--text);font-size:1.05rem;font-weight:400;
  transition:background .15s,color .1s;cursor:pointer;
  position:relative
}
.nav-link:hover{background:var(--hover)}
.nav-link.active{font-weight:600;color:var(--text)}
.nav-link svg{width:1.6rem;height:1.6rem;flex-shrink:0;fill:currentColor}
.nav-icon-active{display:none}
.nav-link.active .nav-icon{display:none}
.nav-link.active .nav-icon-active{display:block}
.bn-item.active .nav-icon{display:none}
.bn-item.active .nav-icon-active{display:block}
.nav-link .notif-badge{
  position:absolute;top:.15rem;left:1.75rem;
  margin-left:0;font-size:.65rem;padding:.05rem .3rem;min-width:.85rem
}
.compose-btn{
  margin:.75rem 0 .5rem;padding:.75rem;border-radius:9999px;background:var(--blue);
  color:#fff;font-weight:600;font-size:.95rem;border:none;cursor:pointer;
  width:100%;text-align:center;transition:background .15s;display:flex;
  align-items:center;justify-content:center;gap:.5rem
}
.compose-btn:hover{background:var(--blue2)}
.compose-btn svg{width:1.1rem;height:1.1rem;fill:#fff;flex-shrink:0}
#nav-user{
  margin-top:auto;display:flex;align-items:center;gap:.6rem;
  padding:.6rem .85rem;border-radius:9999px;flex-shrink:0;
  transition:background .15s;position:relative
}
#nav-user:hover{background:var(--hover)}
#nav-user img{width:36px;height:36px;border-radius:50%;object-fit:cover;flex-shrink:0}
#nav-name{font-weight:600;font-size:.85rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#nav-acct{font-size:.75rem;color:var(--text3);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#nav-user{cursor:pointer}
.nav-user-menu{
  position:absolute;bottom:calc(100% + 8px);left:.5rem;right:.5rem;z-index:20;
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  box-shadow:0 8px 20px rgba(0,0,0,.12);overflow:hidden;animation:dropIn .15s ease
}
.nav-user-menu a,
.nav-user-menu button{
  display:flex;align-items:center;gap:.6rem;padding:.7rem 1rem;
  font-size:.88rem;font-weight:500;color:var(--text);transition:background .12s;
  text-decoration:none;width:100%;border:0;background:transparent;
  font-family:inherit;text-align:left;cursor:pointer
}
.nav-user-menu a:hover,
.nav-user-menu button:hover{background:var(--hover)}
.nav-user-menu a svg,
.nav-user-menu button svg{width:1.1rem;height:1.1rem;fill:currentColor;flex-shrink:0}
.nav-user-menu .nav-menu-danger{color:var(--red)}
.nav-user-menu .nav-menu-danger svg{fill:var(--red)}
.nav-user-menu .post-menu-divider{height:1px;background:var(--border);margin:.2rem 0}

#main-col{
  flex:1;max-width:var(--max-w);
  border-left:1px solid var(--border);border-right:1px solid var(--border);
  min-height:100vh;background:var(--surface)
}

/* Right panel */
#right-col{
  width:var(--right-w);max-width:var(--right-w);flex-shrink:0;
  padding:1rem;position:sticky;top:0;height:100vh;height:100svh;overflow-y:auto;
  align-self:flex-start;border-left:none
}
#right-search-wrap{
  position:relative;margin-bottom:1rem
}
#right-search-wrap svg{
  position:absolute;left:.85rem;top:50%;transform:translateY(-50%);
  width:1rem;height:1rem;fill:var(--text3);pointer-events:none
}
#right-search-input{
  width:100%;padding:.6rem 1rem .6rem 2.5rem;border:none;border-radius:9999px;
  background:var(--hover);color:var(--text);font-size:.88rem;font-family:inherit;cursor:text;
  outline:none
}
#right-search-input:focus{outline:2px solid var(--blue);background:var(--surface)}
.right-card{
  background:var(--hover);border:none;border-radius:16px;
  overflow:hidden;margin-bottom:1rem
}
.right-card-title{
  font-size:.94rem;font-weight:700;color:var(--text);
  padding:.85rem 1rem .4rem
}
.right-trend-item{
  display:flex;flex-direction:column;gap:.1rem;
  padding:.55rem 1rem;cursor:pointer;transition:background .12s
}
.right-trend-item:hover{background:var(--hover)}
.right-trend-item:last-child{border-radius:0 0 var(--radius) var(--radius)}
.right-trend-tag{font-size:.88rem;font-weight:600;color:var(--text)}
.right-trend-count{font-size:.76rem;color:var(--text3)}
.right-suggest-item{
  display:flex;align-items:center;gap:.65rem;
  padding:.65rem 1rem;transition:background .12s
}
.right-suggest-item:hover{background:var(--hover)}
.right-suggest-item:last-child{border-radius:0 0 var(--radius) var(--radius)}
.right-suggest-item img{
  width:38px;height:38px;border-radius:50%;object-fit:cover;flex-shrink:0;cursor:pointer
}
.right-suggest-info{flex:1;min-width:0}
.right-suggest-name{
  font-size:.85rem;font-weight:700;cursor:pointer;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis
}
.right-suggest-name:hover{text-decoration:underline;color:var(--blue)}
.right-suggest-acct{font-size:.75rem;color:var(--text2)}
.right-suggest-follow{
  background:var(--blue);color:#fff;border:none;border-radius:9999px;
  padding:.3rem .75rem;font-size:.8rem;font-weight:600;cursor:pointer;
  flex-shrink:0;transition:opacity .15s;font-family:inherit
}
.right-suggest-follow:hover{opacity:.85}
.right-suggest-follow.following{
  background:transparent;color:var(--text);border:1.5px solid var(--border)
}
@media(max-width:1099px){#right-col{display:none}}

/* Tablet — icon-only sidebar (701–1099px)
   Cobre: iPad Mini portrait (744/768px), iPad Air portrait (820px),
          iPad Pro 11" portrait (834px), iPad Mini landscape (1024px).
   A partir de 1100px (iPad Mini 6 landscape=1133px, iPad Air landscape=1180px,
   iPad Pro landscape) usa o layout desktop completo com coluna direita. */
@media(min-width:701px) and (max-width:1099px){
  :root{--sidebar-w:68px}
  #sidebar{width:68px;padding:.75rem .4rem;align-items:center}
  #main-col{max-width:100%}
  .sidebar-logo span,
  .nav-link span,
  .compose-btn span,
  #nav-name,#nav-acct,
  #nav-user>svg{display:none}
  .nav-link{justify-content:center;padding:.7rem;position:relative}
  .nav-link .notif-badge{left:calc(50% + .5rem);top:.2rem}
  .compose-btn{width:44px;height:44px;padding:0;border-radius:50%;margin:.4rem auto}
  #nav-user{padding:.5rem;justify-content:center;flex-direction:column;gap:0}
}
/* Home timeline tabs */
#home-tabs-bar{
  display:none;flex-direction:row;align-items:stretch;
  position:sticky;top:0;z-index:11;
  background:color-mix(in srgb,var(--surface) 85%,transparent);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-bottom:1px solid var(--border);
  overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch
}
#home-tabs-bar::-webkit-scrollbar{display:none}
.ht-tab{
  flex:1;padding:.8rem 1rem;
  font-size:.9rem;font-weight:500;color:var(--text2);text-align:center;
  background:none;border:none;border-bottom:2px solid transparent;
  cursor:pointer;white-space:nowrap;transition:color .15s;font-family:inherit
}
.ht-tab:hover{color:var(--text)}
.ht-tab.active{color:var(--text);border-bottom:3px solid var(--blue);font-weight:600}
/* Explore search bar */
.explore-search-bar{
  display:flex;align-items:center;gap:.6rem;
  padding:.7rem 1rem;border-bottom:1px solid var(--border);
  position:sticky;top:2.9rem;z-index:10;
  background:color-mix(in srgb,var(--surface) 85%,transparent);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)
}
.explore-search-bar svg{
  width:1.1rem;height:1.1rem;fill:var(--text3);flex-shrink:0
}
.explore-search-bar input{
  flex:1;border:none;background:transparent;font-size:.95rem;
  color:var(--text);font-family:inherit;outline:none
}
.explore-search-bar input::placeholder{color:var(--text3)}
/* Explore tabs */
.explore-tabs{display:flex;border-bottom:1px solid var(--border);position:sticky;top:5.75rem;z-index:9;background:color-mix(in srgb,var(--surface) 85%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
.explore-tab{flex:1;padding:.8rem 0;text-align:center;font-size:.9rem;font-weight:500;color:var(--text2);cursor:pointer;border-bottom:2px solid transparent;transition:color .15s}
.explore-tab:hover{color:var(--text)}
.explore-tab.active{color:var(--text);border-bottom:3px solid var(--blue);font-weight:600}
#settings-tabs{gap:.15rem;overflow-x:auto;scrollbar-width:none;padding:0 .4rem}
#settings-tabs::-webkit-scrollbar{display:none}
#settings-tabs .settings-tab-btn{
  appearance:none;border:0;background:none;font:inherit;flex:0 0 auto;
  padding:.85rem .8rem;white-space:nowrap
}
.explore-people-item{display:flex;align-items:center;gap:.75rem;padding:.85rem 1.25rem;border-bottom:1px solid var(--border);cursor:pointer}
.explore-people-item:hover{background:var(--hover)}
.explore-people-avatar{width:42px;height:42px;border-radius:50%;flex-shrink:0;object-fit:cover}
.explore-people-info{flex:1;min-width:0}
.explore-people-name{font-weight:700;font-size:.95rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.explore-people-acct{color:var(--text2);font-size:.85rem}
.explore-people-bio{color:var(--text2);font-size:.85rem;margin-top:.2rem;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.explore-tag-item{display:flex;align-items:center;justify-content:space-between;padding:.85rem 1.25rem;border-bottom:1px solid var(--border);cursor:pointer}
.explore-tag-item:hover{background:var(--hover)}
.explore-tag-name{font-weight:700;font-size:1rem}
.explore-tag-count{color:var(--text2);font-size:.85rem}
/* Settings page */
.settings-section{padding:1.25rem;border-bottom:1px solid var(--border)}
.settings-title{font-size:1rem;font-weight:700;margin-bottom:1rem;color:var(--text)}
.settings-row{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:.75rem}
.settings-label{font-size:.9rem;color:var(--text2);flex-shrink:0}
.settings-input{flex:1;max-width:260px;padding:.45rem .7rem;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);font-size:.9rem}
.settings-select{flex:1;max-width:260px;padding:.45rem .7rem;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);font-size:.9rem}
.settings-save-btn{margin-top:.25rem;padding:.5rem 1.25rem;border-radius:9999px;font-weight:700;font-size:.88rem;cursor:pointer;background:var(--blue);color:#fff;border:none}
.settings-save-btn:hover{opacity:.85}
.settings-subtitle{margin:1rem 0 .55rem;font-size:.8rem;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.03em}
.settings-actions-row{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.9rem}
.settings-check-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.5rem 1rem;flex:1}
.settings-check-grid label{display:flex;align-items:center;gap:.45rem;font-size:.88rem;color:var(--text)}
.settings-stack{display:grid;gap:.75rem}
.settings-panel{
  border:1px solid var(--border);border-radius:14px;padding:.9rem 1rem;background:var(--bg)
}
.settings-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem}
.settings-panel-title{font-size:.92rem;font-weight:700;color:var(--text)}
.settings-panel-meta{font-size:.8rem;color:var(--text2);margin-top:.2rem}
.settings-pill-row{display:flex;gap:.45rem;flex-wrap:wrap;margin-top:.55rem}
.settings-pill{
  display:inline-flex;align-items:center;padding:.18rem .5rem;border-radius:999px;
  border:1px solid var(--border);background:var(--surface);font-size:.74rem;color:var(--text2)
}
.settings-secret{
  margin-top:.55rem;padding:.55rem .7rem;border-radius:8px;background:var(--surface);
  border:1px solid var(--border);font-size:.82rem;color:var(--text2);word-break:break-all
}
.settings-secret strong{color:var(--text)}
.settings-inline-note{font-size:.82rem;color:var(--text2);margin-top:.5rem}
.settings-token-box{
  margin-top:.75rem;padding:.8rem .9rem;border-radius:12px;
  background:color-mix(in srgb,var(--blue) 8%,var(--surface));border:1px solid var(--border)
}
.settings-token-box code{
  display:block;margin-top:.45rem;padding:.65rem .75rem;border-radius:8px;background:var(--surface);
  color:var(--text);font-size:.82rem;word-break:break-all
}
.settings-token-box pre{
  display:block;margin-top:.45rem;padding:.75rem;border-radius:8px;background:var(--surface);
  color:var(--text);font-size:.8rem;line-height:1.5;overflow:auto;white-space:pre-wrap;
  word-break:break-word;border:1px solid var(--border)
}
.settings-helper{
  margin-top:.45rem;font-size:.8rem;color:var(--text2);line-height:1.45
}
.settings-checkbox-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:.5rem .8rem}
.settings-checkbox-grid label{display:flex;align-items:center;gap:.45rem;font-size:.86rem;color:var(--text)}
.settings-chip-row{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.75rem 0;border-top:1px solid var(--border)}
.settings-chip-row:first-child{margin-top:.25rem}
.settings-chip-remove{padding:.38rem .8rem;border-radius:9999px;border:1px solid var(--border);background:transparent;color:var(--text2);font-size:.8rem;font-weight:600;cursor:pointer;white-space:nowrap}
.settings-chip-remove:hover{border-color:var(--red);color:var(--red)}
.settings-chip-remove.danger{border-color:color-mix(in srgb,var(--red) 35%,var(--border));color:var(--red)}
.settings-empty{padding:.65rem 0;color:var(--text2);font-size:.88rem}
.toggle-btn{position:relative;width:42px;height:24px;border-radius:12px;border:none;background:var(--border);cursor:pointer;padding:0;transition:background .2s}
.toggle-btn.on{background:var(--blue)}
.toggle-knob{position:absolute;top:2px;left:2px;width:20px;height:20px;border-radius:50%;background:#fff;transition:transform .2s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.toggle-btn.on .toggle-knob{transform:translateX(18px)}
/* Conversation cards */
.conv-card{display:flex;align-items:flex-start;gap:.65rem;padding:.75rem .95rem;border-top:1px solid var(--border);cursor:pointer}
.conv-card:first-child{border-top:none}
.conv-card:hover{background:var(--hover)}
.conv-avatar-wrap{position:relative;flex-shrink:0}
.conv-unread-dot{position:absolute;top:0;right:0;width:10px;height:10px;background:var(--blue);border-radius:50%;border:2px solid var(--surface)}
.conv-body{flex:1;min-width:0}
.conv-header{display:flex;justify-content:space-between;align-items:baseline;gap:.5rem}
.conv-name{font-weight:700;font-size:.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.conv-time{color:var(--text2);font-size:.8rem;flex-shrink:0}
.conv-preview{color:var(--text2);font-size:.88rem;margin-top:.2rem;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.conv-preview.unread{color:var(--text);font-weight:600}
#col-header{
  position:sticky;top:0;z-index:10;padding:.75rem 1rem;
  font-size:1.05rem;font-weight:600;
  display:flex;align-items:center;gap:.5rem;
  background:color-mix(in srgb,var(--surface) 85%,transparent);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-bottom:1px solid var(--border)
}
#col-back-btn{
  background:none;border:none;cursor:pointer;padding:.35rem;
  color:var(--text);flex-shrink:0;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  transition:background .15s;width:34px;height:34px
}
#col-back-btn:hover{background:var(--hover)}
#col-back-btn svg{width:1.15rem;height:1.15rem;fill:currentColor}
@media(prefers-color-scheme:dark){
  #right-search-input{background:var(--hover)}
}

/* Status cards */
.status-card{
  padding:var(--status-pad-y,.75rem) var(--status-pad-x,1rem) .6rem;border-top:1px solid var(--border);
  transition:background .12s;display:block
}
.status-card:first-child{border-top:none}
.status-card:not(.status-focal){cursor:pointer}
.status-card:hover{background:var(--hover)}
.status-card.status-focal{background:var(--surface)}
.boost-bar{
  display:flex;align-items:center;gap:.4rem;
  font-size:.82rem;color:var(--text2);margin-bottom:.4rem;padding-left:52px
}
.boost-bar svg{width:1rem;height:1rem;fill:var(--green);flex-shrink:0}
.boost-bar a{color:var(--text2);font-weight:600}
.boost-bar a:hover{color:var(--blue);text-decoration:underline}
.status-inner{display:flex;gap:.65rem}
.status-left{display:flex;flex-direction:column;align-items:center;gap:4px;position:relative}
/* Thread connector line — shown via JS class on the .status-card */
.thread-line-below .status-left::after{
  content:'';display:block;width:2px;flex:1;min-height:8px;
  background:var(--border);border-radius:1px;margin-top:4px
}
.thread-line-above .status-left::before{
  content:'';display:block;width:2px;height:8px;
  background:var(--border);border-radius:1px;margin-bottom:4px;order:-1
}
.avatar{
  width:42px;height:42px;border-radius:50%;object-fit:cover;
  cursor:pointer;flex-shrink:0;display:block
}
.avatar:hover{opacity:.85}
.status-body{flex:1;min-width:0}
.status-header{
  display:flex;align-items:baseline;gap:.25rem;flex-wrap:nowrap;margin-bottom:.25rem
}
.s-name{font-weight:600;font-size:.9rem;cursor:pointer;white-space:nowrap;
  max-width:60%;overflow:hidden;text-overflow:ellipsis}
.s-name:hover{text-decoration:underline}
.s-acct{font-size:.85rem;color:var(--text3);flex:1;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.s-middot{color:var(--text3);font-size:.85rem;flex-shrink:0}
.s-time{font-size:.85rem;color:var(--text3);white-space:nowrap;cursor:pointer}
.s-time:hover{text-decoration:underline;color:var(--blue)}
.s-more-btn{
  margin-left:auto;background:none;border:none;cursor:pointer;
  color:var(--text3);padding:.15rem;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  transition:color .15s,background .15s;flex-shrink:0;position:relative;
  align-self:center
}
.s-more-btn svg{width:.95rem;height:.95rem;fill:currentColor}
.s-more-btn:hover{color:var(--blue);background:var(--blue-bg)}
.vis-icon{font-size:.75rem;color:var(--text3)}
.status-temporary-badge{
  display:inline-flex;align-items:center;gap:.28rem;
  padding:.12rem .45rem;border-radius:9999px;
  border:1px solid color-mix(in srgb,var(--amber) 35%,var(--border));
  background:color-mix(in srgb,var(--amber) 12%,transparent);
  color:color-mix(in srgb,var(--amber) 65%,var(--text));
  font-size:.72rem;font-weight:700;line-height:1;white-space:nowrap;flex-shrink:0
}
.status-temporary-badge svg{width:.78rem;height:.78rem;fill:currentColor;flex-shrink:0}

.reply-indicator{font-size:.82rem;color:var(--text3);margin-bottom:.25rem;display:flex;align-items:center;gap:.25rem}
.reply-indicator svg{width:.82rem;height:.82rem;fill:currentColor;flex-shrink:0}
.reply-to-name{color:var(--text2);cursor:pointer}
.reply-to-name:hover{color:var(--blue);text-decoration:underline}

/* CW */
.cw-bar{
  background:var(--hover);border:1px solid var(--border);border-radius:8px;
  padding:.4rem .75rem;margin-bottom:.5rem;display:flex;align-items:center;
  justify-content:space-between;gap:.5rem;font-size:.88rem
}
.cw-toggle{
  background:none;border:1px solid var(--border);border-radius:9999px;
  padding:.15rem .6rem;font-size:.78rem;cursor:pointer;
  color:var(--text2);flex-shrink:0
}
.cw-toggle:hover{background:var(--blue-bg);border-color:var(--blue);color:var(--blue)}

/* Content */
.s-content{font-size:.9rem;line-height:1.5;word-break:break-word;margin-bottom:.5rem}
.s-content.truncated{max-height:12rem;overflow:hidden;position:relative}
.s-content.truncated::after{
  content:'';position:absolute;bottom:0;left:0;right:0;height:3rem;
  background:linear-gradient(transparent,var(--surface))
}
.show-more-btn{
  background:none;border:none;color:var(--blue);font-size:.85rem;font-weight:600;
  cursor:pointer;padding:.2rem 0;font-family:inherit
}
.show-more-btn:hover{text-decoration:underline}
.s-content a{color:var(--blue)}
.s-content a:hover{text-decoration:underline}
.s-content p{margin-bottom:.35rem}
.s-content p:last-child{margin-bottom:0}
.s-content code,
.quote-content code{
  display:inline-block;
  padding:.08rem .38rem;
  border-radius:6px;
  background:color-mix(in srgb,var(--hover) 70%,var(--surface));
  border:1px solid var(--border);
  color:var(--text);
  font-size:.92em;
  font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
}
.s-content pre,
.quote-content pre{
  margin:.55rem 0;
  padding:.7rem .85rem;
  border-radius:12px;
  background:color-mix(in srgb,var(--hover) 75%,var(--surface));
  border:1px solid var(--border);
  overflow:auto;
}
.s-content pre code,
.quote-content pre code{
  display:block;
  padding:0;
  border:0;
  background:transparent;
}
.s-content blockquote,
.quote-content blockquote{
  margin:.55rem 0;
  padding:.15rem 0 .15rem .85rem;
  border-left:3px solid color-mix(in srgb,var(--blue) 35%,var(--border));
  color:var(--text2);
  background:color-mix(in srgb,var(--hover) 55%,transparent);
  border-radius:0 10px 10px 0;
}
.s-content blockquote p,
.quote-content blockquote p{
  margin-bottom:.25rem;
}
.s-content blockquote p:last-child,
.quote-content blockquote p:last-child{
  margin-bottom:0;
}
.status-focal .s-content{font-size:1.05rem}
.status-focal .status-header{margin-bottom:.35rem}
.focal-meta{
  display:flex;align-items:center;gap:.3rem;
  padding-top:.65rem;border-top:1px solid var(--border);
  margin-top:.65rem;font-size:.82rem;color:var(--text3)
}
.focal-meta time{color:var(--text2)}
.focal-meta .status-temporary-note{color:color-mix(in srgb,var(--amber) 65%,var(--text))}
.focal-stats{
  display:flex;gap:1rem;padding:.5rem 0;font-size:.88rem;color:var(--text2)
}
.focal-stats span{cursor:pointer}
.focal-stats span:hover{text-decoration:underline}
.focal-stats strong{color:var(--text);font-weight:700}

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
.media-item{overflow:hidden;cursor:pointer;background:var(--border);
  display:flex;align-items:center;justify-content:center;min-height:80px}
.media-item img,.media-item video{
  width:100%;height:100%;object-fit:cover;display:block}
.sensitive-overlay{
  background:var(--hover);border-radius:10px;padding:1.5rem;
  text-align:center;margin-bottom:.65rem;cursor:pointer;
  color:var(--text2);font-size:.88rem;border:1px solid var(--border)
}
.sensitive-overlay:hover{background:var(--blue-bg);color:var(--blue)}
.quote-card{
  border:1px solid var(--border);border-radius:12px;padding:.75rem;margin-bottom:.65rem;
  background:var(--surface2);cursor:pointer
}
.quote-card:hover{background:var(--hover)}
.quote-head{display:flex;align-items:center;gap:.55rem;margin-bottom:.45rem}
.quote-avatar{width:28px;height:28px;border-radius:50%;object-fit:cover;flex-shrink:0}
.quote-meta{display:flex;flex-wrap:wrap;gap:.35rem;font-size:.8rem;color:var(--text3)}
.quote-meta strong{color:var(--text);font-weight:700}
.quote-content{font-size:.86rem;line-height:1.45;color:var(--text);word-break:break-word}
.quote-content p{margin-bottom:.25rem}
.quote-content p:last-child{margin-bottom:0}
.quote-flags{display:flex;gap:.4rem;flex-wrap:wrap;margin-top:.5rem}
.quote-badge{
  display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:9999px;
  padding:.15rem .5rem;font-size:.72rem;color:var(--text2);background:var(--surface)
}

/* Link card */
.link-card{
  border:1px solid var(--border);border-radius:10px;overflow:hidden;
  margin-bottom:.65rem;cursor:pointer;transition:background .15s;display:block
}
.link-card:hover{background:var(--hover)}
.link-card img{width:100%;max-height:200px;object-fit:cover;display:block}
.link-card-body{padding:.65rem .85rem}
.link-card-provider{font-size:.75rem;color:var(--text2);margin-bottom:.2rem}
.link-card-title{font-size:.9rem;font-weight:600;color:var(--text);
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.link-card-desc{font-size:.8rem;color:var(--text2);margin-top:.2rem;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}

/* Action bar */
.action-bar{display:flex;gap:0;margin-top:.4rem;margin-left:-.45rem;max-width:280px}
.action-btn{
  display:inline-flex;align-items:center;gap:.3rem;
  background:none;border:none;cursor:pointer;
  color:var(--text3);font-size:.82rem;padding:.35rem .45rem;
  border-radius:9999px;transition:color .15s;
  flex:1;justify-content:flex-start
}
.action-btn svg{width:1.1rem;height:1.1rem;fill:currentColor;flex-shrink:0}
.action-btn:hover{color:var(--text2)}
.action-btn.reply-btn:hover{color:var(--blue)}
.action-btn.boost-btn:hover,.action-btn.boost-btn.active{color:var(--green)}
.action-btn.fav-btn:hover,.action-btn.fav-btn.active{color:var(--pink)}
.action-btn.fav-btn.active svg{animation:likeAnim .35s ease}
@keyframes likeAnim{0%{transform:scale(1)}30%{transform:scale(1.3)}60%{transform:scale(.9)}100%{transform:scale(1)}}
.action-btn:disabled{opacity:.5;cursor:default}
.action-count{font-size:.82rem}

.feed-end,.feed-error{
  padding:2rem;text-align:center;color:var(--text2);font-size:.9rem
}
.feed-error{color:var(--red)}
.feed-loading{padding:1.5rem;text-align:center;color:var(--text2)}

/* Compose modal */
#compose-modal{
  position:fixed;inset:0;z-index:100;display:none;
  align-items:flex-start;justify-content:center;
  padding-top:5vh;background:rgba(0,0,0,0);
  transition:background .18s
}
#compose-modal.open{display:flex;background:rgba(0,0,0,.5)}
#compose-box{
  background:var(--surface);border-radius:16px;width:100%;
  max-width:580px;margin:0 1rem;
  box-shadow:0 20px 25px -5px rgba(0,0,0,.1),0 8px 10px -6px rgba(0,0,0,.1);
  display:flex;flex-direction:column;
  transform:translateY(12px) scale(.97);opacity:0;
  transition:transform .3s cubic-bezier(.16,1,.3,1),opacity .3s cubic-bezier(.16,1,.3,1)
}
#compose-modal.open #compose-box{transform:translateY(0) scale(1);opacity:1}
#compose-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:.85rem 1rem;border-bottom:1px solid var(--border)
}
#compose-header span{font-weight:700}
#compose-header button{
  background:none;border:none;cursor:pointer;color:var(--text2);
  font-size:1.1rem;padding:.25rem;border-radius:50%;
  width:32px;height:32px;display:flex;align-items:center;justify-content:center
}
#compose-header button:hover{background:var(--blue-bg);color:var(--blue)}
#reply-preview{
  padding:.65rem 1rem;border-bottom:1px solid var(--border);
  font-size:.85rem;color:var(--text2)
}
#cw-input{
  margin:.65rem 1rem 0;border:1px solid var(--border);border-radius:8px;
  padding:.5rem .75rem;font-size:.9rem;background:var(--surface);color:var(--text);
  font-family:inherit
}
#cw-input:focus{outline:none;border-color:var(--blue)}
#compose-body{
  display:flex;gap:.65rem;padding:.65rem 1rem;align-items:flex-start
}
#compose-avatar{
  width:38px;height:38px;border-radius:50%;object-fit:cover;flex-shrink:0;margin-top:.3rem
}
#compose-text{
  border:none;border-radius:0;flex:1;
  padding:.3rem 0;font-size:1rem;min-height:110px;resize:vertical;
  font-family:inherit;background:var(--surface);color:var(--text);line-height:1.5
}
#compose-text:focus{outline:none}
#media-previews{
  display:flex;gap:.5rem;flex-wrap:wrap;padding:0 1rem;margin-bottom:.5rem
}
#compose-poll{padding:0 1rem .65rem}
#compose-poll-options{display:grid;gap:.45rem}
.compose-poll-option:disabled{opacity:.75;cursor:not-allowed}
#compose-poll-note{font-size:.82rem;color:var(--text2);margin:.55rem 0 .2rem}
.compose-poll-option{
  width:100%;border:1px solid var(--border);border-radius:10px;padding:.55rem .7rem;
  font-size:.9rem;background:var(--surface);color:var(--text)
}
#compose-poll-controls{
  display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin-top:.55rem;font-size:.82rem;color:var(--text2)
}
#compose-poll-add{
  background:none;border:1px solid var(--border);border-radius:9999px;padding:.3rem .7rem;
  cursor:pointer;color:var(--blue)
}
#compose-poll-add:hover{background:var(--blue-bg)}
#compose-poll-expiration{
  border:1px solid var(--border);border-radius:8px;padding:.25rem .45rem;font-size:.82rem;background:var(--surface);color:var(--text)
}
.media-thumb{position:relative;width:70px;height:70px;border-radius:8px;overflow:hidden}
.media-thumb img{width:100%;height:100%;object-fit:cover}
.media-thumb button{
  position:absolute;top:2px;right:2px;background:rgba(0,0,0,.6);color:#fff;
  border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:.75rem;
  display:flex;align-items:center;justify-content:center
}
#compose-toolbar{
  display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;
  padding:.65rem 1rem;border-top:1px solid var(--border)
}
.tool-btn{
  background:none;border:none;cursor:pointer;color:var(--blue);
  padding:.35rem;border-radius:8px;font-size:.95rem;
  display:flex;align-items:center;justify-content:center
}
.tool-btn:hover{background:var(--blue-bg)}
.tool-btn label{cursor:pointer;display:flex;align-items:center}
#vis-select{
  border:1px solid var(--border);border-radius:8px;padding:.3rem .5rem;
  font-size:.82rem;background:var(--surface);color:var(--text);cursor:pointer
}
#expire-select{
  border:1px solid var(--border);border-radius:8px;padding:.3rem .5rem;
  font-size:.82rem;background:var(--surface);color:var(--text);cursor:pointer;max-width:160px
}
#char-count{font-size:.82rem;color:var(--text2);margin-left:auto}
#char-count.warn{color:var(--amber)}
#char-count.over{color:var(--red)}
#compose-submit{
  background:var(--blue);color:#fff;border:none;border-radius:9999px;
  padding:.5rem 1.25rem;font-weight:700;font-size:.9rem;cursor:pointer;
  transition:background .15s
}
#compose-submit:hover{background:var(--blue2)}
#compose-submit:disabled{opacity:.6;cursor:default}

/* Notifications */
.notif-card{
  display:flex;gap:.75rem;padding:.8rem .95rem;
  border-top:1px solid var(--border);transition:background .12s
}
.notif-card:first-child{border-top:none}
.notif-card:hover{background:var(--hover)}
.notif-icon{width:1.15rem;flex-shrink:0;display:flex;justify-content:center;padding-top:.2rem}
.notif-icon svg{width:1.15rem;height:1.15rem;fill:currentColor}
.notif-type-mention .notif-icon{color:var(--blue)}
.notif-type-reblog .notif-icon{color:var(--green)}
.notif-type-favourite .notif-icon{color:var(--pink)}
.notif-type-follow .notif-icon,.notif-type-follow_request .notif-icon{color:var(--blue)}
.notif-main{display:flex;gap:.7rem;flex:1;min-width:0}
.notif-avatar{width:42px;height:42px;border-radius:50%;object-fit:cover;cursor:pointer;flex-shrink:0}
.notif-body{flex:1;min-width:0}
.notif-head{display:flex;align-items:baseline;gap:.5rem;justify-content:space-between;margin-bottom:.18rem}
.notif-name{font-size:.9rem;font-weight:700;cursor:pointer;color:var(--text)}
.notif-name:hover{text-decoration:underline;color:var(--blue)}
.notif-time{font-size:.76rem;color:var(--text3);flex-shrink:0}
.notif-text{font-size:.84rem;color:var(--text2);margin-bottom:.35rem;line-height:1.35}
.notif-excerpt{
  font-size:.85rem;color:var(--text);line-height:1.4;cursor:pointer;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;
  word-break:break-word
}
.notif-excerpt:hover{color:var(--blue)}
.notif-actions{display:flex;gap:.5rem;margin-top:.5rem}
.btn-accept{
  background:var(--blue);color:#fff;border:none;border-radius:9999px;
  padding:.35rem .85rem;font-size:.82rem;cursor:pointer;font-weight:600
}
.btn-reject{
  background:none;border:1px solid var(--border);border-radius:9999px;
  padding:.35rem .85rem;font-size:.82rem;cursor:pointer;color:var(--text2)
}
.btn-accept:hover{background:var(--blue2)}
.btn-reject:hover{background:var(--blue-bg);border-color:var(--blue);color:var(--blue)}
.poll-box{margin:.8rem 0;border:1px solid var(--border);border-radius:14px;padding:.8rem;background:var(--surface2)}
.poll-meta{font-size:.78rem;color:var(--text3);margin-top:.55rem}
.poll-options{display:grid;gap:.45rem}
.poll-option-btn,.poll-result{
  width:100%;text-align:left;border-radius:10px;padding:.65rem .8rem;font-size:.9rem
}
.poll-option-btn{
  border:1px solid var(--border);background:var(--surface);cursor:pointer;color:var(--text)
}
.poll-option-btn:hover{background:var(--hover);border-color:var(--blue)}
.poll-result{
  position:relative;overflow:hidden;border:1px solid var(--border);background:var(--surface)
}
.poll-result-bar{
  position:absolute;inset:0 auto 0 0;background:color-mix(in srgb,var(--blue) 16%, transparent);pointer-events:none
}
.poll-result-row{position:relative;display:flex;justify-content:space-between;gap:.75rem;z-index:1}
.poll-voted{border-color:var(--blue)}
.poll-vote-btn{
  margin-top:.65rem;background:var(--blue);color:#fff;border:none;border-radius:9999px;
  padding:.45rem .9rem;font-size:.84rem;font-weight:600;cursor:pointer
}
.poll-vote-btn:disabled{opacity:.6;cursor:default}
.poll-secondary-btn{
  margin-top:.65rem;margin-left:.5rem;border:1px solid var(--border);background:var(--surface);
  color:var(--text2);border-radius:9999px;padding:.45rem .9rem;font-size:.84rem;font-weight:600;cursor:pointer
}
.poll-secondary-btn:hover{background:var(--hover);color:var(--text)}
.poll-hidden{display:none}

/* Profile */
.profile-header{border-bottom:1px solid var(--border)}
.profile-banner{height:150px;background:var(--border);overflow:hidden}
.follows-you-badge{
  display:inline-block;background:var(--hover);color:var(--text2);
  font-size:.72rem;font-weight:600;padding:.15rem .5rem;border-radius:4px;
  margin-left:.5rem;vertical-align:middle
}
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
.profile-stat-link{cursor:pointer}
.profile-stat-link:hover strong{text-decoration:underline}
.profile-actions{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.profile-dm-btn{display:flex;align-items:center;justify-content:center;width:2.2rem;height:2.2rem;border-radius:50%;border:1.5px solid var(--border);background:transparent;cursor:pointer;color:var(--text);transition:background .15s,color .15s,border-color .15s}
.profile-dm-btn:hover{background:var(--hover)}
.profile-dm-btn svg{width:1.1rem;height:1.1rem}
.profile-dm-btn.active{border-color:var(--blue);color:var(--blue)}
.profile-dm-btn.active:hover{background:color-mix(in srgb,var(--blue) 10%,transparent)}
.profile-tabs{display:flex;border-bottom:1px solid var(--border);position:sticky;top:2.9rem;z-index:9;background:color-mix(in srgb,var(--surface) 85%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
.profile-tab{flex:1;padding:.75rem 0;text-align:center;font-size:.88rem;font-weight:500;color:var(--text2);cursor:pointer;border-bottom:2px solid transparent;transition:color .15s;background:none;border-top:none;border-left:none;border-right:none;font-family:inherit}
.profile-tab:hover{color:var(--text)}
.profile-tab.active{color:var(--text);border-bottom:3px solid var(--blue);font-weight:600}
.profile-dm-btn:disabled{opacity:.5;cursor:default}
/* Lists popover menu */
.lists-menu-popover{
  position:fixed;z-index:9000;background:var(--surface);border:1px solid var(--border);
  border-radius:12px;box-shadow:0 10px 15px -3px rgba(0,0,0,.1),0 4px 6px -4px rgba(0,0,0,.1);min-width:170px;max-width:260px;
  max-height:280px;overflow-y:auto;padding:.35rem 0
}
.lists-menu-item{
  display:flex;align-items:center;gap:.6rem;padding:.55rem .9rem;
  font-size:.9rem;cursor:pointer;transition:background .12s;user-select:none
}
.lists-menu-item:hover{background:var(--hover)}
.lists-menu-item input[type=checkbox]{
  width:1rem;height:1rem;accent-color:var(--blue);flex-shrink:0;cursor:pointer
}
.lists-menu-empty,.lists-menu-loading,.lists-menu-error{
  padding:.6rem .9rem;font-size:.85rem;color:var(--text2)
}
.follow-btn{
  padding:.45rem 1.1rem;border-radius:9999px;font-weight:600;font-size:.85rem;
  cursor:pointer;transition:all .15s;border:none;
  background:var(--blue);color:#fff;font-family:inherit
}
.follow-btn.following{
  background:transparent;color:var(--text);border:1px solid var(--border)
}
.follow-btn.following:hover{border-color:var(--red);color:var(--red);background:color-mix(in srgb,var(--red) 8%,transparent)}
.focal-stat-link{
  appearance:none;border:0;background:none;padding:0;margin:0;
  color:var(--fg);font:inherit;cursor:pointer;
}
.focal-stat-link:hover{text-decoration:underline}
.follow-btn:hover{opacity:.8}
.follow-btn:disabled{opacity:.5;cursor:default}
.profile-link{
  font-size:.8rem;color:var(--text3);border:none;background:none;
  padding:.3rem 0;text-decoration:none
}
.profile-link:hover{color:var(--blue);text-decoration:underline}

/* Search */
.search-box{
  display:flex;gap:.5rem;padding:1rem 1.25rem;border-bottom:1px solid var(--border)
}
.search-box input{
  flex:1;border:1px solid var(--border);border-radius:9999px;
  padding:.55rem 1rem;font-size:.9rem;background:var(--hover);color:var(--text);
  font-family:inherit
}
.search-box input:focus{outline:none;border-color:var(--blue);background:var(--surface)}
.search-box button{
  background:var(--blue);color:#fff;border:none;border-radius:9999px;
  padding:.55rem 1.15rem;font-weight:600;cursor:pointer;transition:background .15s;font-size:.88rem
}
.search-box button:hover{background:var(--blue2)}
.search-section-title{
  padding:.75rem 1.25rem .35rem;font-size:.8rem;font-weight:700;
  color:var(--text2);text-transform:uppercase;letter-spacing:.05em;
  border-bottom:1px solid var(--border)
}
.account-card{
  display:flex;align-items:center;gap:.75rem;padding:.85rem 1.25rem;
  border-bottom:1px solid var(--border);transition:background .12s
}
.account-card:hover{background:var(--hover)}
.account-card img{width:42px;height:42px;border-radius:50%;object-fit:cover;cursor:pointer;flex-shrink:0}
.account-card-info{flex:1;min-width:0}
.account-card-name{font-weight:700;font-size:.9rem;cursor:pointer}
.account-card-name:hover{text-decoration:underline;color:var(--blue)}
.account-card-acct{font-size:.82rem;color:var(--text2)}
.hashtag-item{
  padding:.75rem 1.25rem;border-bottom:1px solid var(--border);font-size:.9rem
}
.hashtag-item a{color:var(--blue);font-weight:600}
.hashtag-item a:hover{text-decoration:underline}

/* Lightbox */
#lightbox{
  position:fixed;inset:0;z-index:200;display:none;
  align-items:center;justify-content:center;background:rgba(0,0,0,.92);
  opacity:0;transition:opacity .18s
}
#lightbox.open{display:flex;animation:lbIn .18s ease forwards}
@keyframes lbIn{from{opacity:0}to{opacity:1}}
#lb-close{
  position:absolute;top:1rem;right:1rem;background:rgba(255,255,255,.15);
  border:none;color:#fff;font-size:1.25rem;cursor:pointer;border-radius:50%;
  width:2.5rem;height:2.5rem;display:flex;align-items:center;justify-content:center
}
#lb-close:hover{background:rgba(255,255,255,.3)}
#lb-img{max-width:95vw;max-height:95vh;object-fit:contain;border-radius:8px;
  animation:lbImgIn .2s ease forwards}
@keyframes lbImgIn{from{transform:scale(.96);opacity:0}to{transform:scale(1);opacity:1}}

/* List items */
.list-item{
  display:flex;align-items:center;gap:.85rem;padding:1rem 1.25rem;
  border-bottom:1px solid var(--border);cursor:pointer;transition:background .12s
}
.list-item:hover{background:var(--hover)}
.list-item svg{width:1.2rem;height:1.2rem;fill:var(--text2);flex-shrink:0}
.list-item span{flex:1;font-size:.95rem;font-weight:500}
.list-arrow{fill:var(--text3)!important;width:1rem!important;height:1rem!important}

/* Edit profile form */
.edit-profile-form{padding:1.25rem}
.ep-hero{
  display:flex;align-items:center;gap:1rem;padding:1rem 1.1rem;margin-bottom:1rem;
  background:var(--surface);border:1px solid var(--border);border-radius:16px
}
.ep-hero img{
  width:72px;height:72px;border-radius:50%;object-fit:cover;flex-shrink:0;
  border:3px solid var(--surface2)
}
.ep-hero-meta{min-width:0;flex:1}
.ep-hero-name{font-size:1.05rem;font-weight:800;line-height:1.2}
.ep-hero-handle,.ep-help,.ep-counter{font-size:.82rem;color:var(--text2)}
.ep-hero-handle{margin-top:.1rem}
.ep-chip-row{display:flex;gap:.45rem;flex-wrap:wrap;margin-top:.55rem}
.ep-chip{
  display:inline-flex;align-items:center;padding:.22rem .55rem;border-radius:999px;
  background:var(--hover);border:1px solid var(--border);font-size:.74rem;color:var(--text2)
}
.ep-section{
  padding:1rem 1.1rem;margin-bottom:1rem;background:var(--surface);
  border:1px solid var(--border);border-radius:16px
}
.ep-section-title{
  font-size:.82rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em;
  color:var(--text2);margin-bottom:.9rem
}
.ep-field-grid{display:grid;grid-template-columns:1fr 1fr;gap:.85rem 1rem}
.ep-toggle-grid{display:grid;grid-template-columns:1fr;gap:.75rem}
.ep-toggle-row{
  display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;
  padding:1rem 1.05rem;border:1px solid var(--border);border-radius:14px;background:var(--bg)
}
.ep-toggle-copy{min-width:0}
.ep-toggle-copy strong{display:block;font-size:.92rem;line-height:1.25}
.ep-toggle-copy span{display:block;font-size:.82rem;color:var(--text2);margin-top:.28rem;line-height:1.4}
.ep-toggle-row .toggle-btn{flex-shrink:0;margin-top:.1rem}
.ep-inline-meta{display:flex;justify-content:space-between;gap:.75rem;align-items:center;margin-top:.35rem}
.ep-inline-meta .ep-help{margin:0}
.ep-readonly{
  padding:.65rem .85rem;border:1px solid var(--border);border-radius:8px;background:var(--bg);
  color:var(--text2);font-size:.9rem;word-break:break-word
}
.ep-fields{display:grid;gap:.85rem}
.ep-field-row{
  padding:.9rem;border:1px solid var(--border);border-radius:12px;background:var(--bg)
}
.ep-field-row-head{
  display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:.65rem
}
.ep-field-badge{
  display:inline-flex;align-items:center;padding:.18rem .5rem;border-radius:999px;
  background:color-mix(in srgb,var(--green) 14%,transparent);color:var(--green);font-size:.74rem;font-weight:700
}
.ep-field-remove{
  border:1px solid var(--border);background:transparent;color:var(--text2);
  border-radius:999px;padding:.25rem .7rem;font-size:.76rem;cursor:pointer;font-family:inherit
}
.ep-field-remove:hover{border-color:var(--red);color:var(--red)}
.ep-banner{position:relative;border-radius:12px;overflow:hidden;
  background:var(--border);min-height:120px;margin-bottom:1rem;cursor:pointer}
.ep-banner img{width:100%;max-height:160px;object-fit:cover;display:block}
.ep-banner-placeholder{height:120px;display:flex;align-items:center;
  justify-content:center;color:var(--text3);font-size:.85rem}
.ep-banner-overlay{
  position:absolute;inset:0;background:rgba(0,0,0,.4);
  display:flex;align-items:center;justify-content:center;
  opacity:0;transition:opacity .15s
}
.ep-banner:hover .ep-banner-overlay{opacity:1}
.ep-banner-overlay span{color:#fff;font-size:.85rem;font-weight:600}
.ep-avatar-row{display:flex;align-items:center;gap:1rem;margin-bottom:1.25rem}
.ep-avatar-wrap{position:relative;cursor:pointer;flex-shrink:0}
.ep-avatar-wrap img{width:72px;height:72px;border-radius:50%;object-fit:cover;
  border:3px solid var(--surface);display:block}
.ep-avatar-overlay{
  position:absolute;inset:0;border-radius:50%;background:rgba(0,0,0,.45);
  display:flex;align-items:center;justify-content:center;
  opacity:0;transition:opacity .15s
}
.ep-avatar-wrap:hover .ep-avatar-overlay{opacity:1}
.ep-avatar-overlay svg{width:1.2rem;height:1.2rem;fill:#fff}
.ep-field{margin-bottom:1rem}
.ep-field label{display:block;font-size:.78rem;color:var(--text2);
  margin-bottom:.35rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.ep-field input,.ep-field textarea{
  width:100%;padding:.6rem .85rem;border:1px solid var(--border);
  border-radius:8px;font-size:.9rem;background:var(--surface);color:var(--text);
  font-family:inherit;resize:vertical
}
.ep-field input:focus,.ep-field textarea:focus{
  outline:none;border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-bg)
}
.ep-actions{display:flex;align-items:center;gap:1rem;margin-top:1.5rem}
.ep-save-btn{
  padding:.65rem 1.5rem;background:var(--blue);color:#fff;border:none;
  border-radius:9999px;font-weight:700;font-size:.9rem;cursor:pointer;
  transition:background .15s;font-family:inherit
}
.ep-save-btn:hover{background:var(--blue2)}
.ep-save-btn:disabled{opacity:.6;cursor:default}
.ep-status{font-size:.82rem;color:var(--text2)}
.ep-status.ok{color:var(--green)}
.ep-status.err{color:var(--red)}
@media (max-width:720px){
  .ep-hero{align-items:flex-start}
  .ep-field-grid,.ep-toggle-grid{grid-template-columns:1fr}
  .ep-toggle-row{padding:.9rem}
}

/* List management */
.lists-toolbar{
  display:flex;align-items:center;justify-content:space-between;
  padding:.85rem 1.25rem;border-bottom:1px solid var(--border)
}
.lists-toolbar h2{font-size:.9rem;font-weight:700;color:var(--text2);
  text-transform:uppercase;letter-spacing:.05em}
.btn-new-list{
  display:inline-flex;align-items:center;gap:.3rem;padding:.4rem .85rem;
  background:var(--blue);color:#fff;border:none;border-radius:9999px;
  font-size:.82rem;font-weight:700;cursor:pointer;transition:background .15s;font-family:inherit
}
.btn-new-list:hover{background:var(--blue2)}
.list-item{
  display:flex;align-items:center;gap:.75rem;padding:.85rem 1.25rem;
  border-bottom:1px solid var(--border);cursor:pointer;transition:background .12s
}
.list-item:hover{background:var(--hover)}
.list-item-icon{width:1.1rem;height:1.1rem;fill:var(--text3);flex-shrink:0}
.list-item-title{flex:1;font-size:.95rem;font-weight:500}
.list-actions{display:flex;gap:.25rem;flex-shrink:0}
.list-act-btn{
  background:none;border:none;cursor:pointer;padding:.35rem;border-radius:6px;
  color:var(--text2);transition:background .15s,color .15s
}
.list-act-btn:hover{background:var(--hover);color:var(--text)}
.list-act-btn.del:hover{background:color-mix(in srgb,var(--red) 12%,transparent);color:var(--red)}
.list-act-btn svg{width:1rem;height:1rem;fill:currentColor;display:block}
.list-drag-handle{
  display:flex;align-items:center;padding:.2rem .15rem;cursor:grab;flex-shrink:0;
  color:var(--text3);opacity:.5;touch-action:none
}
.list-drag-handle:hover{opacity:1;color:var(--text2)}
.list-drag-handle svg{width:1rem;height:1rem;fill:currentColor;display:block;pointer-events:none}
.list-item.dragging{opacity:.4}
.list-item.drag-over{border-top:2px solid var(--blue);margin-top:-2px}
.members-header{
  display:flex;align-items:center;gap:.75rem;padding:.85rem 1.25rem;
  border-bottom:1px solid var(--border)
}
.members-back{background:none;border:none;cursor:pointer;padding:.3rem;
  border-radius:6px;color:var(--text2);transition:color .15s;display:flex}
.members-back:hover{color:var(--blue)}
.members-back svg{width:1.3rem;height:1.3rem;fill:currentColor}
.members-title{font-weight:700;font-size:1rem}
.members-search{
  display:flex;gap:.5rem;padding:.75rem 1.25rem;border-bottom:1px solid var(--border)
}
.members-search input{
  flex:1;padding:.5rem .85rem;border:1px solid var(--border);border-radius:9999px;
  font-size:.88rem;background:var(--surface);color:var(--text);font-family:inherit
}
.members-search input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-bg)}
.members-search button{
  padding:.5rem .9rem;background:var(--blue);color:#fff;border:none;
  border-radius:9999px;font-size:.82rem;font-weight:700;cursor:pointer;font-family:inherit
}
.member-row{
  display:flex;align-items:center;gap:.75rem;padding:.75rem 1.25rem;
  border-bottom:1px solid var(--border)
}
.member-row img{width:40px;height:40px;border-radius:50%;object-fit:cover;flex-shrink:0;cursor:pointer}
.member-info{flex:1;min-width:0}
.member-name{font-weight:600;font-size:.88rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
.member-name:hover{color:var(--blue);text-decoration:underline}
.member-acct{font-size:.78rem;color:var(--text2)}
.member-remove{
  background:none;border:1px solid var(--border);border-radius:9999px;
  padding:.3rem .65rem;font-size:.75rem;color:var(--text2);cursor:pointer;
  transition:all .15s;white-space:nowrap;flex-shrink:0
}
.member-remove:hover{border-color:var(--red);color:var(--red)}
.member-add{
  background:var(--blue);border:none;border-radius:9999px;
  padding:.3rem .65rem;font-size:.75rem;color:#fff;cursor:pointer;
  transition:background .15s;white-space:nowrap;flex-shrink:0
}
.member-add:hover{background:var(--blue2)}

/* Bottom nav (mobile only — hidden on desktop) */
#bottom-nav{display:none}
#bs-overlay{display:none;position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.45)}
#bottom-sheet{
  display:none;position:fixed;bottom:0;left:0;right:0;z-index:61;
  background:var(--surface);border-radius:16px 16px 0 0;
  border-top:1px solid var(--border);
  padding-bottom:env(safe-area-inset-bottom,0px);
  transform:translateY(100%);transition:transform .28s cubic-bezier(.4,0,.2,1)
}
#bottom-sheet.open{transform:translateY(0)}
#bs-handle{
  width:40px;height:4px;background:var(--border);border-radius:9999px;
  margin:.75rem auto .5rem
}
.bs-item{
  display:flex;align-items:center;gap:1rem;padding:.8rem 1.5rem;
  color:var(--text);font-size:.95rem;font-weight:500;cursor:pointer;
  transition:background .12s;text-decoration:none;-webkit-tap-highlight-color:transparent;
  background:transparent;border:0;width:100%;text-align:left;
  appearance:none;-webkit-appearance:none;border-radius:0
}
.bs-item svg{width:1.3rem;height:1.3rem;fill:var(--text2);flex-shrink:0}
.bs-item:hover{background:var(--blue-bg);color:var(--blue)}
.bs-item:hover svg{fill:var(--blue)}
.bs-item.active,.bs-item.active svg{color:var(--blue);fill:var(--blue)}
.bs-divider{height:1px;background:var(--border);margin:.3rem 0}
.bs-logout,
.bs-logout span{
  color:var(--red)!important;
  -webkit-text-fill-color:var(--red);
}
.bs-logout svg{fill:var(--red)!important}
.bs-logout:hover,
.bs-logout:focus,
.bs-logout:active{
  background:color-mix(in srgb,var(--red) 10%,transparent)!important;
  color:var(--red)!important;
  -webkit-text-fill-color:var(--red);
  outline:none;
}
.bs-logout:hover svg,
.bs-logout:focus svg,
.bs-logout:active svg{
  fill:var(--red)!important;
}

/* Mobile */
@media(max-width:700px){
  #sidebar{display:none}
  #main-col{max-width:100%;padding-bottom:calc(54px + env(safe-area-inset-bottom,0px))}

  #main-col{border-left:none;border-right:none}
  #bottom-nav{
    display:flex;align-items:stretch;
    position:fixed;bottom:0;left:0;right:0;z-index:50;
    background:color-mix(in srgb,var(--surface) 85%,transparent);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    border-top:1px solid var(--border);
    padding-bottom:env(safe-area-inset-bottom,0px)
  }
  .bn-item{
    flex:1;display:flex;flex-direction:column;align-items:center;
    justify-content:center;padding:.65rem .25rem;
    color:var(--text2);
    border:none;background:none;cursor:pointer;transition:color .15s;
    text-decoration:none;position:relative
  }
  .bn-item span{display:none}
  .bn-item svg{width:1.7rem;height:1.7rem;flex-shrink:0}
  .bn-item .notif-badge{
    position:absolute;top:.35rem;left:52%;
    margin-left:.25rem;font-size:.7rem;padding:.1rem .32rem;min-width:.95rem
  }
  .bn-item:hover,.bn-item.active{color:var(--text)}

  #new-posts-pill{top:3.5rem}
  #bs-overlay.open{display:block}
  #bottom-sheet{display:block}
  #settings-tabs{top:0;padding:0 .2rem}
  #settings-tabs .settings-tab-btn{padding:.8rem .7rem;font-size:.86rem}
  .settings-row{flex-direction:column;align-items:stretch}
  .settings-input,.settings-select{max-width:none;width:100%}
}

/* Focus-visible — acessibilidade por teclado */
:focus-visible{outline:2px solid var(--blue);outline-offset:2px;border-radius:4px}
button:focus-visible,a:focus-visible{outline:2px solid var(--blue);outline-offset:-1px;border-radius:4px}

/* Remover hovers em dispositivos touch-only */
@media(hover:none){
  .status-card:hover,.nav-link:hover,.notif-card:hover,
  .account-card:hover,.list-item:hover,.bs-item:hover{background:transparent}
  .nav-link:hover{color:inherit}
}

/* Respect reduced motion preferences */
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.01ms !important;
    animation-iteration-count:1 !important;
    transition-duration:.01ms !important
  }
  #compose-box{transform:none !important}
}

/* Toast notifications */
#toast-container{
  position:fixed;bottom:1.5rem;left:50%;transform:translateX(-50%);z-index:300;
  display:flex;flex-direction:column;gap:.4rem;pointer-events:none;
  width:max-content;max-width:calc(100vw - 2rem)
}
.toast{
  padding:.6rem 1.15rem;border-radius:9999px;font-size:.85rem;font-weight:500;
  color:#fff;background:rgba(15,20,25,.92);backdrop-filter:blur(8px);
  animation:toastIn .2s ease;white-space:nowrap;max-width:100%;text-align:center;
  box-shadow:0 4px 12px rgba(0,0,0,.15)
}
.toast.err{background:rgba(233,22,70,.92)}
.toast.ok{background:rgba(9,179,94,.92)}
@keyframes toastIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

/* Scroll sentinel (infinite scroll) */
.scroll-sentinel{height:3rem;visibility:hidden}

/* Floating "New posts" pill (Bluesky-style) */
#new-posts-pill{
  display:none;position:fixed;top:4.5rem;left:50%;transform:translateX(-50%);z-index:15;
  background:var(--blue);color:#fff;border:none;border-radius:9999px;
  padding:.5rem 1.25rem;font-size:.85rem;font-weight:600;cursor:pointer;
  font-family:inherit;box-shadow:0 4px 14px rgba(0,133,255,.35);
  animation:pillIn .25s ease;white-space:nowrap
}
#new-posts-pill:hover{background:var(--blue2)}
@keyframes pillIn{from{opacity:0;transform:translateX(-50%) translateY(-8px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}

/* ALT badge on media */
.alt-badge{
  position:absolute;bottom:6px;left:6px;background:rgba(0,0,0,.7);color:#fff;
  font-size:.65rem;font-weight:700;padding:.1rem .35rem;border-radius:4px;
  letter-spacing:.03em;pointer-events:none;line-height:1.3
}
.media-item{position:relative}

/* Post fade-in animation */
.status-card{animation:fadeInPost .25s ease}
@keyframes fadeInPost{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}

/* Repost dropdown */
.repost-dropdown{
  position:absolute;bottom:calc(100% + 4px);left:0;z-index:20;
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  box-shadow:0 8px 20px rgba(0,0,0,.12);min-width:180px;
  overflow:hidden;animation:dropIn .15s ease
}
@keyframes dropIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}
.repost-option{
  display:flex;align-items:center;gap:.6rem;padding:.7rem 1rem;
  cursor:pointer;font-size:.88rem;font-weight:500;color:var(--text);
  transition:background .12s;border:none;background:none;width:100%;
  font-family:inherit;text-align:left
}
.repost-option:hover{background:var(--hover)}
.repost-option svg{width:1.1rem;height:1.1rem;fill:currentColor;flex-shrink:0}
.boost-btn{position:relative}
.post-menu-dropdown{
  position:absolute;top:calc(100% + 4px);right:0;left:auto;z-index:20;
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  box-shadow:0 8px 20px rgba(0,0,0,.12);min-width:200px;
  overflow:hidden;animation:dropIn .15s ease
}
.post-menu-divider{height:1px;background:var(--border);margin:.2rem 0}
.post-menu-danger{color:var(--red)!important}
.post-menu-danger svg{fill:var(--red)!important}

/* Notification badge */
.notif-badge{
  background:var(--blue);color:#fff;font-size:.65rem;font-weight:600;
  border-radius:9999px;padding:.1rem .38rem;min-width:1.15rem;
  text-align:center;margin-left:auto;flex-shrink:0;line-height:1.4
}

/* Skeleton loading */
.skeleton-card{display:flex;gap:.85rem;padding:1rem 1.25rem;border-bottom:1px solid var(--border)}
.sk-avatar{width:44px;height:44px;border-radius:50%;flex-shrink:0}
.sk-body{flex:1;display:flex;flex-direction:column;gap:.55rem;padding-top:.2rem}
.sk-line{height:.75rem;border-radius:4px}
.sk-avatar,.sk-line{
  background:linear-gradient(90deg,var(--border) 25%,color-mix(in srgb,var(--border) 60%,var(--bg)) 50%,var(--border) 75%);
  background-size:200% 100%;animation:shimmer 1.5s infinite
}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}

/* Keyboard-navigation focus ring */
.status-card.focused{outline:2px solid var(--blue);outline-offset:-2px;border-radius:4px}

/* Toast undo button */
.toast-undo{
  background:none;border:1px solid rgba(255,255,255,.5);color:#fff;
  border-radius:4px;padding:.1rem .5rem;margin-left:.5rem;
  cursor:pointer;font-size:.82rem;font-family:inherit
}
.toast-undo:hover{background:rgba(255,255,255,.15)}

/* Mobile FAB compose button */
#mobile-fab{
  display:none;position:fixed;z-index:49;
  bottom:calc(62px + env(safe-area-inset-bottom,0px));right:1rem;
  width:56px;height:56px;border-radius:50%;border:none;
  background:var(--blue);cursor:pointer;
  box-shadow:0 4px 14px rgba(0,133,255,.4);
  transition:background .15s,transform .15s;
  align-items:center;justify-content:center
}
#mobile-fab:hover{background:var(--blue2)}
#mobile-fab:active{transform:scale(.92)}
#mobile-fab svg{width:24px;height:24px}
@media(max-width:700px){#mobile-fab{display:flex}}

/* Pull-to-refresh indicator */
#ptr-indicator{
  position:fixed;top:0;left:0;right:0;z-index:100;text-align:center;
  padding:.5rem;font-size:.82rem;color:var(--text2);font-weight:500;
  opacity:0;pointer-events:none;background:var(--surface);
  border-bottom:1px solid var(--border)
}

/* Login page */
.login-wrap{max-width:400px;margin:5vh auto;padding:1rem}
.login-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:16px;padding:2rem
}
.login-title{font-size:1.1rem;font-weight:700;margin-bottom:1.5rem;color:var(--text)}
.login-field{margin-bottom:1rem}
.login-field label{display:block;font-size:.85rem;color:var(--text2);margin-bottom:.35rem;font-weight:500}
.login-field input{
  width:100%;padding:.65rem 1rem;border:1px solid var(--border);
  border-radius:9999px;font-size:.95rem;background:var(--surface);color:var(--text);
  font-family:inherit
}
.login-field input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-bg)}
.login-error{
  background:#fff0f0;border:1px solid var(--red);border-radius:8px;
  padding:.65rem .85rem;font-size:.85rem;color:var(--red);margin-bottom:1rem
}
@media(prefers-color-scheme:dark){.login-error{background:rgba(244,33,46,.1)}}
.login-submit{
  width:100%;padding:.75rem;background:var(--blue);color:#fff;border:none;
  border-radius:9999px;font-weight:700;font-size:1rem;cursor:pointer;
  transition:background .15s;margin-top:.5rem
}
.login-submit:hover{background:var(--blue2)}
.login-foot{margin-top:1rem;color:var(--text2);font-size:.88rem;text-align:center}
.login-foot a,.login-alt-link{color:var(--blue)}
.login-alt-link{font-size:.9rem;font-weight:600}
CSS;
    }

    // ── JavaScript ────────────────────────────────────────────────────────────

    private function js(): string
    {
        return <<<'JS'
'use strict';
const WCFG = window.__WCFG__;
const UIPREFS = {
    expandMedia: 'default',
    expandSpoilers: false,
    autoplayGifs: false,
};
const USERPREFS = {
    defaultVisibility: 'public',
    defaultSensitive: false,
    defaultLanguage: null,
    defaultExpireAfter: null,
};
let _pendingExploreQuery = '';
function storageGet(key, fallback = null) {
    try {
        const value = window.localStorage.getItem(key);
        return value === null ? fallback : value;
    } catch (e) {
        return fallback;
    }
}

function storageSet(key, value) {
    try {
        window.localStorage.setItem(key, value);
        return true;
    } catch (e) {
        return false;
    }
}
function userScopedStorageKey(key) {
    return WCFG?.myId ? key + ':' + WCFG.myId : key;
}
function userStorageGet(key, fallback = null) {
    return storageGet(userScopedStorageKey(key), fallback);
}
function userStorageSet(key, value) {
    return storageSet(userScopedStorageKey(key), value);
}
const APP_APPEARANCE = {
    theme: storageGet('appearanceTheme', 'system') || 'system',
    density: storageGet('appearanceDensity', 'comfortable') || 'comfortable',
    width: storageGet('appearanceWidth', 'default') || 'default',
    textSize: storageGet('appearanceTextSize', 'default') || 'default',
};

// ── Helpers ────────────────────────────────────────────────────────────────
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const escJsSq = s => String(s ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/</g, '\\x3C')
    .replace(/>/g, '\\x3E');

function prefBool(v) {
    return v === true || v === 1 || v === '1' || v === 'true';
}

function applyReadingPrefs(prefs = {}) {
    USERPREFS.defaultVisibility = prefs['posting:default:visibility'] || 'public';
    USERPREFS.defaultSensitive = prefBool(prefs['posting:default:sensitive']);
    USERPREFS.defaultLanguage = prefs['posting:default:language'] || null;
    const expireAfter = Number(prefs['posting:default:expire_after'] ?? 0);
    USERPREFS.defaultExpireAfter = expireAfter > 0 ? expireAfter : null;
    const expandMedia = prefs['reading:expand:media'];
    UIPREFS.expandMedia = ['default', 'show_all', 'hide_all'].includes(expandMedia) ? expandMedia : 'default';
    UIPREFS.expandSpoilers = prefBool(prefs['reading:expand:spoilers']);
    UIPREFS.autoplayGifs = prefBool(prefs['reading:autoplay:gifs']);
}

function applyAppearancePrefs() {
    const root = document.documentElement;
    root.dataset.themePref = APP_APPEARANCE.theme;
    root.style.colorScheme = APP_APPEARANCE.theme === 'system' ? 'light dark' : APP_APPEARANCE.theme;
    root.style.setProperty('--status-pad-y', APP_APPEARANCE.density === 'compact' ? '.55rem' : '.75rem');
    root.style.setProperty('--status-pad-x', APP_APPEARANCE.density === 'compact' ? '.85rem' : '1rem');
    root.style.setProperty('--max-w', APP_APPEARANCE.width === 'wide' ? '720px' : APP_APPEARANCE.width === 'narrow' ? '540px' : '600px');
    root.style.setProperty('--ui-font-scale', APP_APPEARANCE.textSize === 'large' ? '1.08' : APP_APPEARANCE.textSize === 'small' ? '.94' : '1');
}

function saveAppearancePrefs() {
    const ok = [
        storageSet('appearanceTheme', APP_APPEARANCE.theme),
        storageSet('appearanceDensity', APP_APPEARANCE.density),
        storageSet('appearanceWidth', APP_APPEARANCE.width),
        storageSet('appearanceTextSize', APP_APPEARANCE.textSize),
    ].every(Boolean);
    applyAppearancePrefs();
    return ok;
}

async function loadReadingPrefs() {
    try {
        applyReadingPrefs(await Api.get('/api/v1/preferences'));
    } catch {}
}

function timeAgo(iso) {
    const d = new Date(iso), diff = (Date.now() - d) / 1000;
    if (diff < 60)     return Math.round(diff) + 's';
    if (diff < 3600)   return Math.round(diff / 60) + 'm';
    if (diff < 86400)  return Math.round(diff / 3600) + 'h';
    if (diff < 604800) return Math.round(diff / 86400) + 'd';
    return d.toLocaleDateString('en-GB', {day:'numeric', month:'short'});
}

function formatDate(iso) {
    return new Date(iso).toLocaleString('en-GB', {year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
}

function htmlToPlainText(html) {
    const div = document.createElement('div');
    div.innerHTML = String(html ?? '')
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<\/p>/gi, '\n\n')
        .replace(/<\/div>/gi, '\n');
    return (div.textContent || div.innerText || '').trim();
}

async function copyText(value) {
    if (!value) throw new Error('Nothing to copy.');
    if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        return;
    }
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    ta.style.pointerEvents = 'none';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand('copy');
    ta.remove();
    if (!ok) throw new Error('Could not copy to clipboard.');
}

function parseCsvRow(line) {
    const out = [];
    let cur = '';
    let quote = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
            if (quote && line[i + 1] === '"') {
                cur += '"';
                i++;
            } else {
                quote = !quote;
            }
            continue;
        }
        if (!quote && (ch === ',' || ch === ';' || ch === '\t')) {
            out.push(cur.trim());
            cur = '';
            continue;
        }
        cur += ch;
    }
    out.push(cur.trim());
    return out.map(cell => cell.replace(/^"|"$/g, '').trim());
}

// ── Toast ──────────────────────────────────────────────────────────────────
const Toast = {
    show(msg, type = '', dur = 3200) {
        const c = document.getElementById('toast-container');
        if (!c) return;
        const t = document.createElement('div');
        t.className = 'toast' + (type ? ' ' + type : '');
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(() => {
            t.style.transition = 'opacity .3s';
            t.style.opacity = '0';
            setTimeout(() => t.remove(), 320);
        }, dur);
    },
    err(msg) { this.show(msg, 'err'); },
    ok(msg)  { this.show(msg, 'ok'); },
};

// ── API ────────────────────────────────────────────────────────────────────
const Api = {
    async _fetch(method, path, body) {
        const opts = {method, credentials: 'same-origin', headers: {Authorization: 'Bearer ' + WCFG.token}};
        if (body instanceof FormData) {
            opts.body = body;
        } else if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const r = await fetch(path, opts);
        if (!r.ok) {
            const t = await r.text();
            let msg = r.status + '';
            try { const j = JSON.parse(t); msg = j.error || j.message || msg; } catch {}
            throw new Error(msg);
        }
        if (r.status === 204) return null;
        const t = await r.text();
        if (!t) return null;
        try { return JSON.parse(t); } catch { return t; }
    },
    async _fetchPage(method, path, body) {
        const opts = {method, credentials: 'same-origin', headers: {Authorization: 'Bearer ' + WCFG.token}};
        if (body instanceof FormData) {
            opts.body = body;
        } else if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const r = await fetch(path, opts);
        if (!r.ok) {
            const t = await r.text();
            let msg = r.status + '';
            try { const j = JSON.parse(t); msg = j.error || j.message || msg; } catch {}
            throw new Error(msg);
        }
        const t = await r.text();
        let data = null;
        if (t) {
            try { data = JSON.parse(t); } catch { data = t; }
        }
        return {data, nextMaxId: parseNextMaxId(r.headers.get('Link'))};
    },
    get(path, params = {}) {
        const filtered = Object.fromEntries(
            Object.entries(params).filter(([, v]) => v !== false && v !== null && v !== undefined)
        );
        const qs = new URLSearchParams(filtered).toString();
        return this._fetch('GET', qs ? path + '?' + qs : path);
    },
    getPage(path, params = {}) {
        const filtered = Object.fromEntries(
            Object.entries(params).filter(([, v]) => v !== false && v !== null && v !== undefined)
        );
        const qs = new URLSearchParams(filtered).toString();
        return this._fetchPage('GET', qs ? path + '?' + qs : path);
    },
    post(path, body) { return this._fetch('POST', path, body); },
    del(path, body)  { return this._fetch('DELETE', path, body); },
    patch(path, body){ return this._fetch('PATCH',  path, body); },
    put(path, body)  { return this._fetch('PUT',    path, body); },
};

function parseNextMaxId(linkHeader) {
    if (!linkHeader) return null;
    for (const part of linkHeader.split(',')) {
        if (!/;\s*rel="?next"?/i.test(part)) continue;
        const m = part.match(/<([^>]+)>/);
        if (!m) continue;
        try {
            return new URL(m[1], window.location.origin).searchParams.get('max_id');
        } catch {
            return null;
        }
    }
    return null;
}

// ── Render: media grid ─────────────────────────────────────────────────────
function renderMediaGrid(attachments, sensitive) {
    if (!attachments || !attachments.length) return '';
    const items = attachments.map(a => {
        const isVideo = a.type === 'video' || a.type === 'gifv';
        const thumb = esc(a.preview_url || a.url);
        const full  = esc(a.url);
        const alt   = esc(a.description || '');
        if (isVideo) {
            const autoplay = UIPREFS.autoplayGifs ? ' autoplay muted loop' : '';
            return `<div class="media-item"><video src="${full}" poster="${thumb}" controls playsinline${autoplay} style="width:100%;height:100%;object-fit:cover"></video></div>`;
        }
        const altBadge = a.description ? '<span class="alt-badge">ALT</span>' : '';
        return `<div class="media-item"><img src="${thumb}" alt="${alt}" loading="lazy" data-full-src="${full}" data-alt="${alt}">${altBadge}</div>`;
    });
    return `<div class="media-grid count-${Math.min(attachments.length, 4)}">${items.join('')}</div>`;
}

// ── Render: link card ──────────────────────────────────────────────────────
function renderCard(card) {
    if (!card || !card.url) return '';
    const img      = card.image ? `<img src="${esc(card.image)}" alt="" loading="lazy">` : '';
    const provider = card.provider_name ? `<div class="link-card-provider">${esc(card.provider_name)}</div>` : '';
    const desc     = card.description ? `<div class="link-card-desc">${esc(card.description)}</div>` : '';
    return `<a class="link-card" href="${esc(card.url)}" target="_blank" rel="noopener noreferrer">${img}<div class="link-card-body">${provider}<div class="link-card-title">${esc(card.title)}</div>${desc}</div></a>`;
}

function renderQuote(quote) {
    if (!quote || !quote.account) return '';
    const acct = quote.account;
    const mediaCount = Math.min((quote.media_attachments || []).length, 4);
    const mediaBadge = mediaCount ? `<span class="quote-badge">${mediaCount} media</span>` : '';
    const pollBadge = quote.poll ? '<span class="quote-badge">Poll</span>' : '';
    return `<div class="quote-card" onclick="event.stopPropagation();navigate('THREAD','${escJsSq(quote.id)}')">
        <div class="quote-head">
            <img class="quote-avatar" src="${esc(acct.avatar)}" alt="" loading="lazy">
            <div class="quote-meta"><strong>${esc(acct.display_name || acct.username)}</strong><span>@${esc(acct.acct)}</span></div>
        </div>
        <div class="quote-content">${quote.content || '<p></p>'}</div>
        ${(mediaBadge || pollBadge) ? `<div class="quote-flags">${mediaBadge}${pollBadge}</div>` : ''}
    </div>`;
}

function renderPoll(poll, statusId) {
    if (!poll) return '';
    const totalVotes = Number(poll.votes_count || 0);
    const ownVotes = new Set((poll.own_votes || []).map(v => String(v)));
    const canVote = !poll.expired && !poll.voted;
    const hasPublicResults = (poll.options || []).some(opt => opt.votes_count !== null && opt.votes_count !== undefined);
    const voteOptionsHtml = (poll.options || []).map((opt, idx) => {
        const selected = ownVotes.has(String(idx));
        if (canVote) {
            const control = poll.multiple
                ? `<input type="checkbox" name="choices[]" value="${idx}" ${selected ? 'checked' : ''} onclick="event.stopPropagation()">`
                : `<input type="radio" name="choices[]" value="${idx}" ${selected ? 'checked' : ''} onclick="event.stopPropagation()">`;
            return `<label class="poll-option-btn${selected ? ' poll-voted' : ''}" onclick="event.stopPropagation()">${control} <span>${esc(opt.title || '')}</span></label>`;
        }
        return '';
    }).join('');
    const resultOptionsHtml = (poll.options || []).map((opt, idx) => {
        const selected = ownVotes.has(String(idx));
        const votes = Number(opt.votes_count || 0);
        const pct = totalVotes > 0 ? Math.round((votes / totalVotes) * 100) : 0;
        return `<div class="poll-result${selected ? ' poll-voted' : ''}">
            <div class="poll-result-bar" style="width:${pct}%"></div>
            <div class="poll-result-row"><span>${esc(opt.title || '')}</span><strong>${votes}${totalVotes > 0 ? ' · ' + pct + '%' : ''}</strong></div>
        </div>`;
    }).join('');

    const metaBits = [];
    metaBits.push(poll.multiple ? 'Multiple choice' : 'Single choice');
    metaBits.push(`${totalVotes} voto${totalVotes === 1 ? '' : 's'}`);
    if (poll.expires_at && !poll.expired) metaBits.push('Ends ' + timeAgo(poll.expires_at));
    if (poll.expired) metaBits.push('Closed');
    const showResultsByDefault = !canVote;

    return `<div class="poll-box" data-poll-id="${esc(poll.id)}" data-status-id="${esc(statusId)}">
        <form class="poll-form" onsubmit="submitPollVote(event,'${escJsSq(poll.id)}','${escJsSq(statusId)}')">
            <div class="poll-options${showResultsByDefault ? ' poll-hidden' : ''}" data-poll-view="vote">${voteOptionsHtml}</div>
            <div class="poll-options${showResultsByDefault ? '' : ' poll-hidden'}" data-poll-view="results">${resultOptionsHtml}</div>
            ${canVote ? `<button class="poll-vote-btn${showResultsByDefault ? ' poll-hidden' : ''}" data-poll-view="vote" type="submit">Vote</button>` : ''}
            ${canVote && hasPublicResults ? `<button class="poll-secondary-btn" type="button" onclick="togglePollResults(this)">View results</button>` : ''}
            <div class="poll-meta">${esc(metaBits.join(' · '))}</div>
        </form>
    </div>`;
}

function togglePollResults(btn) {
    event?.stopPropagation?.();
    const form = btn.closest('.poll-form');
    if (!form) return;
    const voteEls = form.querySelectorAll('[data-poll-view="vote"]');
    const resultEls = form.querySelectorAll('[data-poll-view="results"]');
    const showingResults = Array.from(resultEls).some(el => !el.classList.contains('poll-hidden'));
    voteEls.forEach(el => el.classList.toggle('poll-hidden', !showingResults));
    resultEls.forEach(el => el.classList.toggle('poll-hidden', showingResults));
    btn.textContent = showingResults ? 'View results' : 'Back to voting';
}

// ── Render: status card ────────────────────────────────────────────────────
function renderStatus(s, focal = false) {
    const isBoost = !!s.reblog;
    const post    = isBoost ? s.reblog : s;
    const acct    = post.account;

    const boostBar = isBoost ? `
        <div class="boost-bar">
            <svg viewBox="0 0 24 24"><path d="M17 1L21 5L17 9V6H7V12H5V6C5 4.9 5.9 4 7 4H17V1ZM7 23L3 19L7 15V18H17V12H19V18C19 19.1 18.1 20 17 20H7V23Z"/></svg>
            <a onclick="navigate('PROFILE','${escJsSq(s.account.id)}')" style="cursor:pointer">${esc(s.account.display_name || s.account.username)}</a> repostou
        </div>` : '';

    const visMap = {
        unlisted: '<svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" style="vertical-align:middle"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>',
        private:  '<svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" style="vertical-align:middle"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>',
        direct:   '<svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" style="vertical-align:middle"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>',
    };
    const visBadge = post.visibility !== 'public' ? `<span class="vis-icon" title="${esc(post.visibility)}">${visMap[post.visibility] || ''}</span>` : '';
    const temporaryBadge = post.expires_at ? `
        <span class="status-temporary-badge" title="Deletes ${esc(formatDate(post.expires_at))}">
            <svg viewBox="0 0 24 24"><path d="M12 7V12L15.2 13.9L14.45 15.13L10.5 12.75V7H12ZM12 2C6.48 2 2 6.48 2 12S6.48 22 12 22 22 17.52 22 12 17.52 2 12 2ZM12 20C7.59 20 4 16.41 4 12S7.59 4 12 4 20 7.59 20 12 16.41 20 12 20Z"/></svg>
            Temporary
        </span>` : '';
    const temporaryMeta = post.expires_at
        ? `<span class="status-temporary-note" title="Deletes ${esc(formatDate(post.expires_at))}">Deletes ${timeAgo(post.expires_at)}</span>`
        : '';

    const hasCW = !!post.spoiler_text;
    const collapseCW = hasCW && !UIPREFS.expandSpoilers;
    const cwBar = hasCW ? `<div class="cw-bar"><span>${esc(post.spoiler_text)}</span><button class="cw-toggle" onclick="toggleCWContent(this)">${collapseCW ? 'Show more' : 'Hide content'}</button></div>` : '';

    const contentStyle = collapseCW ? 'display:none' : '';

    const hasMedia = (post.media_attachments || []).length > 0;
    const shouldHideAllMedia = UIPREFS.expandMedia === 'hide_all' && hasMedia;
    const isSensitive = post.sensitive && hasMedia && !hasCW;
    const shouldHideSensitive = isSensitive && UIPREFS.expandMedia !== 'show_all';
    const hideMediaByDefault = shouldHideAllMedia || shouldHideSensitive;
    const overlayLabel = shouldHideSensitive
        ? 'Sensitive media — click to view'
        : 'Media hidden by default — click to view';
    const sensitiveBtn = hideMediaByDefault ? `<button class="sensitive-overlay" onclick="this.nextElementSibling.style.display='';this.remove()">🫣 ${overlayLabel}</button>` : '';

    const mediaHtml = hasMedia ? renderMediaGrid(post.media_attachments) : '';
    const pollHtml  = post.poll ? renderPoll(post.poll, post.id) : '';
    const quoteHtml = post.quote ? renderQuote(post.quote) : '';
    const _norm = u => u ? u.replace(/\/+$/, '').toLowerCase() : '';
    const _cardUrl = _norm(post.card?.url);
    const isHandleCard = post.card && (post.mentions || []).some(m => _norm(m.url) === _cardUrl || _cardUrl.endsWith('/@' + m.username.toLowerCase()));
    const cardHtml  = !post.media_attachments?.length && post.card && !isHandleCard ? renderCard(post.card) : '';

    const replyAcct = post.in_reply_to_account_id
        ? (post.mentions || []).find(m => m.id === post.in_reply_to_account_id)
        : null;
    const replyTo = post.in_reply_to_id
        ? `<div class="reply-indicator"><svg viewBox="0 0 24 24"><path d="M10 9V5l-7 7 7 7v-4.1c5 0 8.5 1.6 11 5.1-1-5-4-10-11-11z"/></svg> Replying to ${replyAcct ? '<span class="reply-to-name" onclick="navigate(\'PROFILE\',\'' + escJsSq(replyAcct.id) + '\')">@' + esc(replyAcct.username) + '</span>' : 'a post'}</div>`
        : '';

    const isOwn    = post.account.id === WCFG.myId;
    const canBoost = post.visibility !== 'private' && post.visibility !== 'direct';

    const rc = post.replies_count   > 0 ? `<span class="action-count">${post.replies_count}</span>`   : '';
    const bc = post.reblogs_count   > 0 ? `<span class="action-count">${post.reblogs_count}</span>`   : '';
    const fc = post.favourites_count > 0 ? `<span class="action-count">${post.favourites_count}</span>` : '';


    const favPath = post.favourited
        ? 'M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z'
        : 'M16.5 3c-1.74 0-3.41.81-4.5 2.09C10.91 3.81 9.24 3 7.5 3 4.42 3 2 5.42 2 8.5c0 3.78 3.4 6.86 8.55 11.54L12 21.35l1.45-1.32C18.6 15.36 22 12.28 22 8.5 22 5.42 19.58 3 16.5 3zm-4.4 15.55l-.1.1-.1-.1C7.14 14.24 4 11.39 4 8.5 4 6.5 5.5 5 7.5 5c1.54 0 3.04.99 3.57 2.36h1.87C13.46 5.99 14.96 5 16.5 5c2 0 3.5 1.5 3.5 3.5 0 2.89-3.14 5.74-7.9 10.05z';

    const bmPath = post.bookmarked
        ? 'M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z'
        : 'M17 3H7c-1.1 0-1.99.9-1.99 2L5 21l7-3 7 3V5c0-1.1-.9-2-2-2zm0 15l-5-2.18L7 18V5h10v13z';

    // Focal-specific sections (thread detail view)
    const focalMeta = focal ? `
        <div class="focal-meta"><time>${esc(formatDate(post.created_at))}</time>${visBadge ? ' · ' + visBadge : ''}${temporaryMeta ? ' · ' + temporaryMeta : ''}</div>
        ${(post.reblogs_count > 0 || post.favourites_count > 0) ? `<div class="focal-stats">
            ${post.reblogs_count > 0 ? `<button type="button" class="focal-stat-link" onclick="event.stopPropagation();showRebloggedBy('${escJsSq(post.id)}')"><strong>${post.reblogs_count}</strong> ${post.reblogs_count === 1 ? 'repost' : 'reposts'}</button>` : ''}
            ${post.favourites_count > 0 ? `<button type="button" class="focal-stat-link" onclick="event.stopPropagation();showFavouritedBy('${escJsSq(post.id)}')"><strong>${post.favourites_count}</strong> ${post.favourites_count === 1 ? 'like' : 'likes'}</button>` : ''}
        </div>` : ''}` : '';

    return `
    <div class="status-card${focal ? ' status-focal' : ''}" data-id="${esc(post.id)}"${focal ? '' : ` onclick="handleCardClick(event,'${escJsSq(post.id)}')"`}>
        ${boostBar}
        <div class="status-inner">
            <div class="status-left">
                <img class="avatar" src="${esc(acct.avatar)}" alt="" loading="lazy" onclick="navigate('PROFILE','${escJsSq(acct.id)}')" title="@${esc(acct.acct)}">
            </div>
            <div class="status-body">
                <div class="status-header">
                    <span class="s-name" onclick="navigate('PROFILE','${escJsSq(acct.id)}')">${esc(acct.display_name || acct.username)}</span>
                    <span class="s-acct">@${esc(acct.acct)}</span>
                    ${temporaryBadge}
                    ${focal ? '' : `${visBadge}<span class="s-middot">·</span>
                    <span class="s-time" onclick="navigate('THREAD','${escJsSq(post.id)}')" title="${esc(formatDate(post.created_at))}">${timeAgo(post.created_at)}</span>`}
                    <button class="s-more-btn" onclick="event.stopPropagation();showPostMenu(event,'${escJsSq(post.id)}',${post.bookmarked ? 'true' : 'false'},${isOwn ? 'true' : 'false'},'${escJsSq(post.url)}')" aria-label="More options">
                        <svg viewBox="0 0 24 24"><path d="M6 10c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm12 0c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm-6 0c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                    </button>
                </div>
                ${replyTo}
                ${cwBar}
                <div class="cw-wrapper">
                    <div class="cw-content" style="${contentStyle}">
                        <div class="s-content${!focal && (post.content || '').length > 600 ? ' truncated' : ''}">${post.content || ''}</div>
                        ${!focal && (post.content || '').length > 600 ? '<button class="show-more-btn" onclick="event.stopPropagation();this.previousElementSibling.classList.remove(\'truncated\');this.remove()">Show more</button>' : ''}
                        ${quoteHtml}
                        ${pollHtml}
                        ${hideMediaByDefault ? sensitiveBtn : ''}
                        ${mediaHtml ? `<div style="${hideMediaByDefault ? 'display:none' : ''}">${mediaHtml}</div>` : ''}
                        ${cardHtml}
                    </div>
                </div>
                ${focalMeta}
                <div class="action-bar">
                    <button class="action-btn reply-btn" onclick="Compose.openReply('${escJsSq(post.id)}','${escJsSq(acct.acct)}')" title="Reply" aria-label="Reply">
                        <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>${rc}
                    </button>
                    <button class="action-btn boost-btn${post.reblogged ? ' active' : ''}" onclick="showRepostMenu(event,'${escJsSq(post.id)}',this)" title="Repostar" aria-label="Repostar"${!canBoost ? ' disabled' : ''}>
                        <svg viewBox="0 0 24 24"><path d="M17 1L21 5L17 9V6H7V12H5V6C5 4.9 5.9 4 7 4H17V1ZM7 23L3 19L7 15V18H17V12H19V18C19 19.1 18.1 20 17 20H7V23Z"/></svg>${bc}
                    </button>
                    <button class="action-btn fav-btn${post.favourited ? ' active' : ''}" onclick="toggleFav('${escJsSq(post.id)}',this)" title="Gostar" aria-label="Gostar">
                        <svg viewBox="0 0 24 24"><path d="${favPath}"/></svg>${fc}
                    </button>
                </div>
            </div>
        </div>
    </div>`;
}

// ── Render: notification ───────────────────────────────────────────────────
function renderNotification(n) {
    const type  = n.type;
    const actor = n.account;
    const icons = {
        mention:        '<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10h5v-2h-5c-4.34 0-8-3.66-8-8s3.66-8 8-8 8 3.66 8 8v1.43c0 .79-.71 1.57-1.5 1.57s-1.5-.78-1.5-1.57V12c0-2.76-2.24-5-5-5s-5 2.24-5 5 2.24 5 5 5c1.38 0 2.64-.56 3.54-1.47.65.89 1.77 1.47 2.96 1.47 1.97 0 3.5-1.6 3.5-3.57V12c0-5.52-4.48-10-10-10zm0 13c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3z"/></svg>',
        reblog:         '<svg viewBox="0 0 24 24"><path d="M17 1L21 5L17 9V6H7V12H5V6C5 4.9 5.9 4 7 4H17V1ZM7 23L3 19L7 15V18H17V12H19V18C19 19.1 18.1 20 17 20H7V23Z"/></svg>',
        favourite:      '<svg viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></svg>',
        follow:         '<svg viewBox="0 0 24 24"><path d="M15 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm-9-2V7H4v3H1v2h3v3h2v-3h3v-2H6zm9 4c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>',
        follow_request: '<svg viewBox="0 0 24 24"><path d="M15 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm-9-2V7H4v3H1v2h3v3h2v-3h3v-2H6zm9 4c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>',
    };
    const labels = {
        mention:        'mencionou-te',
        reblog:         'reposted your post',
        favourite:      'favorited your post',
        follow:         'started following you',
        follow_request: 'pediu para te seguir',
    };
    const actorName  = esc(actor.display_name || actor.username);
    const rawExcerpt = n.status ? (n.status.spoiler_text || htmlToPlainText(n.status.content || '')) : '';
    const excerpt    = rawExcerpt.substring(0, 80);
    const notifTime  = n.created_at
        ? `<time class="notif-time" title="${esc(formatDate(n.created_at))}">${timeAgo(n.created_at)}</time>`
        : '';
    const followReqBtns = type === 'follow_request' ? `
        <div class="notif-actions">
            <button class="btn-accept" onclick="approveFollowRequest('${escJsSq(actor.id)}',this)">Aceitar</button>
            <button class="btn-reject" onclick="rejectFollowRequest('${escJsSq(actor.id)}',this)">Rejeitar</button>
        </div>` : '';
    const excerptHtml = excerpt ? `<div class="notif-excerpt" onclick="navigate('THREAD','${escJsSq(n.status?.id || '')}')">${esc(excerpt)}${excerpt.length >= 80 ? '…' : ''}</div>` : '';
    const statusId = String(n.status?.id || '');
    const cardClick = statusId ? ` onclick="handleNotificationCardClick(event,'${escJsSq(statusId)}')"` : '';

    return `
    <div class="notif-card notif-type-${esc(type)}"${cardClick}>
        <div class="notif-icon">${icons[type] || ''}</div>
        <div class="notif-main">
            <img class="notif-avatar" src="${esc(actor.avatar)}" alt="" onclick="navigate('PROFILE','${escJsSq(actor.id)}')">
            <div class="notif-body">
                <div class="notif-head">
                    <strong class="notif-name" onclick="navigate('PROFILE','${escJsSq(actor.id)}')">${actorName}</strong>
                    ${notifTime}
                </div>
                <div class="notif-text">${labels[type] || esc(type)}</div>
                ${excerptHtml}
                ${followReqBtns}
            </div>
        </div>
    </div>`;
}

function handleNotificationCardClick(event, statusId) {
    if (!statusId) return;
    if (event.target.closest('button, a, img, strong, .notif-actions, .notif-excerpt')) return;
    navigate('THREAD', statusId);
}

// ── Render: profile header ─────────────────────────────────────────────────
function renderProfileHeader(account, rel) {
    const isOwn      = account.id === WCFG.myId;
    const banner     = account.header && !account.header.includes('missing.png')
        ? `<img src="${esc(account.header)}" alt="" loading="lazy">` : '';
    const isFollowing = rel?.following ?? false;
    const isRequested = rel?.requested ?? false;
    const isNotifying = rel?.notifying ?? false;
    const dmBtn = !isOwn
        ? `<button class="profile-dm-btn" onclick="Compose.openDM('${escJsSq(account.acct)}')" title="Enviar mensagem direta">
            <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>
           </button>` : '';
    const notifyBtn = (!isOwn && isFollowing)
        ? `<button class="profile-dm-btn profile-follow-only${isNotifying ? ' active' : ''}"
            data-notifying="${isNotifying ? '1' : '0'}"
            title="${isNotifying ? 'Disable post notifications' : 'Enable post notifications'}"
            onclick="toggleNotify('${escJsSq(account.id)}',this)">
            <svg viewBox="0 0 24 24" fill="currentColor"><path d="${isNotifying
                ? 'M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6V11c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z'
                : 'M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6V11c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2zM17 13.58V11c0-2.28-1.47-4.22-3.54-4.78C11.02 5.65 9 7.32 9 9.5c0 .39.08.76.19 1.12L17 13.58z'
            }"/></svg>
           </button>` : '';
    const listsBtn = (!isOwn && isFollowing)
        ? `<button class="profile-dm-btn profile-follow-only" title="Add to lists"
            onclick="showListsMenu('${escJsSq(account.id)}',this)">
            <svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg>
           </button>` : '';
    const actionBtn  = isOwn
        ? `<button class="follow-btn" onclick="navigate('EDIT_PROFILE')">Edit profile</button>`
        : `<button class="follow-btn${isFollowing ? ' following' : ''}${isRequested && !isFollowing ? ' following' : ''}"
            data-following="${isFollowing ? '1' : '0'}"
            data-requested="${isRequested ? '1' : '0'}"
            data-account-id="${esc(account.id)}"
            onclick="toggleFollow('${escJsSq(account.id)}',this)"
            onmouseenter="if(this.dataset.following==='1')this.textContent='Unfollow'"
            onmouseleave="if(this.dataset.following==='1')this.textContent='Following'">
            ${isFollowing ? 'Following' : (isRequested ? 'Requested' : 'Follow')}
        </button>`;
    const bio            = account.note || '';
    const postsCount     = account.statuses_count ?? 0;
    const followersCount = account.followers_count ?? 0;
    const followingCount = account.following_count ?? 0;

    return `
    <div class="profile-header">
        <div class="profile-banner">${banner}</div>
        <div class="profile-meta">
            <div class="profile-avatar-wrap">
                <img class="profile-avatar" src="${esc(account.avatar)}" alt="">
            </div>
            <div class="profile-name">${esc(account.display_name || account.username)}</div>
            <div class="profile-acct">@${esc(account.acct)}${!isOwn && rel?.followed_by ? '<span class="follows-you-badge">Follows you</span>' : ''}</div>
            <div class="profile-bio">${bio}</div>
            ${account.fields?.length ? `<div class="profile-fields">${account.fields.map(f => `<div class="profile-field"><span class="profile-field-name">${esc(f.name)}</span><span class="profile-field-value${f.verified_at ? ' profile-field-verified' : ''}">${f.value || ''}</span></div>`).join('')}</div>` : ''}
            <div class="profile-stats">
                <span><strong>${postsCount}</strong> posts</span>
                <span class="profile-stat-link" onclick="navigate('FOLLOWERS','${escJsSq(account.id)}')"><strong>${followersCount}</strong> followers</span>
                <span class="profile-stat-link" onclick="navigate('FOLLOWING','${escJsSq(account.id)}')"><strong>${followingCount}</strong> following</span>
            </div>
            <div class="profile-actions">
                ${actionBtn}
                ${notifyBtn}
                ${listsBtn}
                ${dmBtn}
                <a class="profile-link" href="${esc(account.url)}" target="_blank" rel="noopener">View public profile ↗</a>
            </div>
        </div>
        <div class="profile-tabs">
            <button class="profile-tab active" data-ptab="posts" onclick="switchProfileTab('${escJsSq(account.id)}','posts',this)">Posts</button>
            <button class="profile-tab" data-ptab="replies" onclick="switchProfileTab('${escJsSq(account.id)}','replies',this)">Replies</button>
            <button class="profile-tab" data-ptab="media" onclick="switchProfileTab('${escJsSq(account.id)}','media',this)">Media</button>
            ${isOwn ? `<button class="profile-tab" data-ptab="likes" onclick="switchProfileTab('${escJsSq(account.id)}','likes',this)">Likes</button>` : ''}
        </div>
    </div>`;
}

// ── Render: account card (search results) ──────────────────────────────────
function renderAccount(a) {
    return `
    <div class="account-card">
        <img src="${esc(a.avatar)}" alt="" onclick="navigate('PROFILE','${escJsSq(a.id)}')">
        <div class="account-card-info">
            <div class="account-card-name" onclick="navigate('PROFILE','${escJsSq(a.id)}')">${esc(a.display_name || a.username)}</div>
            <div class="account-card-acct">@${esc(a.acct)}</div>
        </div>
    </div>`;
}

// ── Skeleton loading ───────────────────────────────────────────────────────
function skeletonHtml(n = 3) {
    return Array.from({length: n}, () => `
    <div class="skeleton-card">
        <div class="sk-avatar"></div>
        <div class="sk-body">
            <div class="sk-line" style="width:38%"></div>
            <div class="sk-line" style="width:92%"></div>
            <div class="sk-line" style="width:66%"></div>
        </div>
    </div>`).join('');
}

// ── Keyboard navigation ────────────────────────────────────────────────────
let _focusedCard = null;

function focusCard(card) {
    if (_focusedCard) _focusedCard.classList.remove('focused');
    _focusedCard = card;
    if (card) {
        card.classList.add('focused');
        card.scrollIntoView({block: 'nearest', behavior: 'smooth'});
    }
}

// ── State & feed loading ───────────────────────────────────────────────────
let _maxId = null, _currentEndpoint = null, _currentEndpointParams = {}, _loading = false, _searchDebounce = null;
let _searchReqSeq = 0, _exploreSearchReqSeq = 0, _memberSearchReqSeq = 0;

// ── View cache (scroll position preservation) ──────────────────────────────
// Stores rendered content + scroll position so navigating back doesn't reload.
const _pageCache = new Map();
const _PAGE_CACHE_MAX = 6;

function _cacheCurrentView() {
    const view = WCFG.view || 'HOME';
    const key  = view === 'HOME' ? 'HOME:' + _homeTab : view + ':' + (WCFG.viewId || '');
    const col = document.getElementById('col-content');
    if (!col || !WCFG.view) return;

    // Find the first status card at or near the top of the visible area.
    // Save its ID and how far its top edge was below the sticky header, so we
    // can restore the exact visual position regardless of image load order.
    const headerH = document.getElementById('col-header')?.offsetHeight || 56;
    let anchorId = null, anchorOffset = 0;
    for (const card of col.querySelectorAll('.status-card[data-id]')) {
        const rect = card.getBoundingClientRect();
        if (rect.bottom > headerH) {          // first card at least partially visible
            anchorId     = card.dataset.id;
            anchorOffset = rect.top - headerH; // px between header-bottom and card-top (can be negative)
            break;
        }
    }

    // Save clean header text (strip back-button text if present)
    const hdrEl   = document.getElementById('col-header');
    const hdrText = hdrEl?.querySelector('span')?.textContent ?? hdrEl?.textContent ?? '';
    const hdrBack = !!document.getElementById('col-back-btn');

    _pageCache.set(key, {
        html:        col.innerHTML,
        scrollY:     window.scrollY,
        anchorId,
        anchorOffset,
        maxId:       _maxId,
        endpoint:    _currentEndpoint,
        renderFn:    _currentRenderFn,
        headerText:  hdrText,
        headerBack:  hdrBack,
    });
    if (_pageCache.size > _PAGE_CACHE_MAX) {
        _pageCache.delete(_pageCache.keys().next().value);
    }
}

function _restoreCachedView(view, id) {
    // For HOME, each tab has its own cache entry keyed by _homeTab
    // (caller must set _homeTab before calling this)
    const key = view === 'HOME' ? 'HOME:' + _homeTab : view + ':' + (id || '');
    const cached = _pageCache.get(key);
    if (!cached) return false;

    const col = document.getElementById('col-content');
    col.innerHTML    = cached.html;
    _maxId           = cached.maxId;
    _currentEndpoint = cached.endpoint;
    _currentRenderFn = cached.renderFn;

    if (cached.headerText) setColHeader(cached.headerText, cached.headerBack);

    // Reconnect IntersectionObserver for infinite scroll
    if (_observer) { _observer.disconnect(); _observer = null; }
    col.querySelector('.scroll-sentinel')?.remove();
    if (_maxId && _currentEndpoint) addLoadMoreBtn();

    // Restore scroll by anchor element.
    // Images above the anchor card may not be loaded yet (lazy), so we also
    // re-correct scroll each time one of them finishes loading.
    const _scrollToAnchor = () => {
        if (!cached.anchorId) { window.scrollTo({top: cached.scrollY, behavior: 'auto'}); return; }
        const card = col.querySelector(`.status-card[data-id="${cached.anchorId}"]`);
        if (!card)             { window.scrollTo({top: cached.scrollY, behavior: 'auto'}); return; }
        const headerH = document.getElementById('col-header')?.offsetHeight || 56;
        const targetScrollY = card.getBoundingClientRect().top + window.scrollY - headerH - cached.anchorOffset;
        window.scrollTo({top: Math.max(0, targetScrollY), behavior: 'auto'});
    };

    requestAnimationFrame(() => requestAnimationFrame(() => {
        _scrollToAnchor();

        // Re-correct as images above the anchor finish loading (they shift layout).
        if (cached.anchorId) {
            const card = col.querySelector(`.status-card[data-id="${cached.anchorId}"]`);
            if (card) {
                const imgs = Array.from(col.querySelectorAll('img')).filter(img =>
                    !img.complete &&
                    (card.compareDocumentPosition(img) & Node.DOCUMENT_POSITION_PRECEDING)
                );
                if (imgs.length) {
                    let pending = imgs.length;
                    const onSettle = () => {
                        _scrollToAnchor();
                        if (--pending <= 0) imgs.forEach(i => { i.onload = null; i.onerror = null; });
                    };
                    imgs.forEach(i => { i.onload = onSettle; i.onerror = onSettle; });
                }
            }
        }
    }));
    return true;
}

function setColHeader(t, showBack = false, backAction = 'history.back()') {
    const hdr = document.getElementById('col-header');
    if (showBack) {
        hdr.innerHTML = `<button id="col-back-btn" onclick="${backAction}" aria-label="Retroceder"><svg viewBox="0 0 24 24"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg></button><span>${t}</span>`;
    } else {
        hdr.textContent = t;
    }
    document.title = t + ' · ' + WCFG.domain;
}

function clearContent() {
    _maxId = null; _currentEndpoint = null; _currentEndpointParams = {}; _loading = false;
    _focusedCard = null;
    document.getElementById('col-content').innerHTML = '';
    document.getElementById('home-tabs-bar').style.display = 'none';
    document.getElementById('col-header').style.display = '';
}

async function loadFeed(endpoint, renderFn, params = {}) {
    if (_loading) return;
    _loading = true;
    const p = {limit: 20, ...params};
    if (_maxId) p.max_id = _maxId;
    // Show skeleton cards on first page load
    if (!_maxId) {
        const content  = document.getElementById('col-content');
        const sentinel = content.querySelector('.scroll-sentinel');
        const tmp = document.createElement('div');
        tmp.innerHTML = skeletonHtml(4);
        while (tmp.firstElementChild) {
            sentinel ? content.insertBefore(tmp.firstElementChild, sentinel) : content.appendChild(tmp.firstElementChild);
        }
    }
    try {
        const page = await Api.getPage(endpoint, p);
        const items = Array.isArray(page.data) ? page.data : [];
        document.querySelectorAll('#col-content .skeleton-card').forEach(el => el.remove());
        if (!items.length) {
            insertBeforeLoadMore('<div class="feed-end">No more posts.</div>');
            removeLoadMoreBtn(); _loading = false; return;
        }
        _maxId = page.nextMaxId || items[items.length - 1].id;
        _currentEndpoint = endpoint;
        items.forEach(item => insertBeforeLoadMore(renderFn(item)));
        if (page.nextMaxId === null && items.length < p.limit) removeLoadMoreBtn();
    } catch (e) {
        document.querySelectorAll('#col-content .skeleton-card').forEach(el => el.remove());
        insertBeforeLoadMore('<div class="feed-error">Error: ' + esc(e.message) + '</div>');
    }
    _loading = false;
}

function insertBeforeLoadMore(html) {
    const content = document.getElementById('col-content');
    const sentinel = content.querySelector('.scroll-sentinel');
    const tmp = document.createElement('div');
    tmp.innerHTML = html;
    const node = tmp.firstElementChild;
    if (!node) return;
    if (sentinel) content.insertBefore(node, sentinel);
    else content.appendChild(node);
}

function prependToFeed(html) {
    const content = document.getElementById('col-content');
    if (!content) return;
    content.querySelectorAll('.feed-end,.feed-error').forEach(el => el.remove());
    const sentinel = content.querySelector('.scroll-sentinel');
    const tmp = document.createElement('div');
    tmp.innerHTML = html;
    const node = tmp.firstElementChild;
    if (!node) return;
    if (content.firstElementChild === sentinel) {
        content.insertBefore(node, sentinel);
        return;
    }
    if (sentinel) content.insertBefore(node, content.firstElementChild || sentinel);
    else content.insertBefore(node, content.firstElementChild);
}

function prependToProfile(status) {
    const content = document.getElementById('col-content');
    if (!content) return false;
    const header = content.querySelector('.profile-header');
    if (!header) return false;
    content.querySelectorAll('.feed-end,.feed-error').forEach(el => el.remove());
    const tmp = document.createElement('div');
    tmp.innerHTML = renderStatus(status);
    const node = tmp.firstElementChild;
    if (!node) return false;
    const afterHeader = header.nextElementSibling;
    if (afterHeader) content.insertBefore(node, afterHeader);
    else content.appendChild(node);

    const stats = header.querySelector('.profile-stats span strong');
    if (stats) {
        const current = parseInt(stats.textContent || '0', 10);
        if (!Number.isNaN(current)) stats.textContent = String(current + 1);
    }
    return true;
}

let _observer = null;

function addLoadMoreBtn() {
    if (document.querySelector('.scroll-sentinel')) return;
    const sentinel = document.createElement('div');
    sentinel.className = 'scroll-sentinel';
    document.getElementById('col-content').appendChild(sentinel);
    _observer = new IntersectionObserver(entries => {
        if (entries[0].isIntersecting && _currentEndpoint && !_loading) {
            loadFeed(_currentEndpoint, _currentRenderFn, _currentEndpointParams);
        }
    }, {rootMargin: '300px'});
    _observer.observe(sentinel);
}

function removeLoadMoreBtn() {
    _observer?.disconnect();
    _observer = null;
    document.querySelector('.scroll-sentinel')?.remove();
}

let _currentRenderFn = renderStatus;

let _homeTab   = 'home';   // active tab id: 'home' | 'local' | list-id
let _homeLists = null;     // cached list of user lists

async function refreshAfterCreate(status) {
    if (!status?.id) {
        Toast.ok('Posted.');
        return;
    }

    if (WCFG.view === 'HOME') {
        // Only mutate the current feed in-place when the newly created post
        // is actually expected to belong to the active home tab.
        const belongsToCurrentTab =
            _homeTab === 'home' ||
            (_homeTab === 'local' && status.visibility === 'public');
        if (belongsToCurrentTab) {
            prependToFeed(renderStatus(status));
            window.scrollTo({top: 0, behavior: 'smooth'});
        }
        Toast.ok('Posted.');
        return;
    }

    if (WCFG.view === 'PROFILE' && (!WCFG.viewId || WCFG.viewId === WCFG.myId)) {
        if (!prependToProfile(status)) {
            showProfile(WCFG.viewId || WCFG.myId);
        }
        window.scrollTo({top: 0, behavior: 'smooth'});
        Toast.ok('Posted.');
        return;
    }

    if (WCFG.view === 'THREAD') {
        await dispatchView('THREAD', WCFG.viewId || status.id);
        Toast.ok('Posted.');
        return;
    }

    Toast.ok('Posted.');
}

async function showHome(tabId) {
    if (tabId !== undefined) {
        const tabChanged = tabId !== _homeTab;
        // If clicking the already-active tab, scroll to top and refresh (Bluesky UX)
        if (tabId === _homeTab && WCFG.view === 'HOME') {
            window.scrollTo({top: 0, behavior: 'smooth'});
        }
        _homeTab = tabId;
        const cur = history.state || {};
        history.replaceState({...cur, view: 'HOME', homeTab: _homeTab}, '');
        if (tabChanged) {
            _pendingPosts = 0;
            updateNewPostsBtn();
        }
    } else if (_homeTab === 'home') {
        const savedDefault = userStorageGet('defaultHomeTab', 'home') || 'home';
        if (savedDefault === 'local' && userStorageGet('showLocalTab', '0') === '1') {
            _homeTab = 'local';
        } else if (savedDefault === 'federated' && userStorageGet('showFederatedTab', '0') === '1') {
            _homeTab = 'federated';
        } else if (savedDefault === 'trending') {
            _homeTab = 'trending';
        }
    }
    _pendingPosts = 0; updateNewPostsBtn();
    setColHeader('Home'); clearContent(); _currentRenderFn = renderStatus;
    await _renderHomeTabBar();
    addLoadMoreBtn();
    const ep = _homeTab === 'home'       ? '/api/v1/timelines/home'
             : _homeTab === 'local'      ? '/api/v1/timelines/public'
             : _homeTab === 'federated'  ? '/api/v1/timelines/public'
             : _homeTab === 'trending'   ? '/api/v1/trends/statuses'
             : '/api/v1/timelines/list/' + _homeTab;
    const params = _homeTab === 'local'
        ? {local: true}
        : _homeTab === 'federated'
            ? {remote: true}
            : {};
    _currentEndpointParams = params;
    await loadFeed(ep, renderStatus, params);
}

async function _renderHomeTabBar() {
    const bar = document.getElementById('home-tabs-bar');
    // Fetch lists once and cache
    if (_homeLists === null) {
        try { _homeLists = await Api.get('/api/v1/lists'); }
        catch { _homeLists = []; }
    }
    const tabs = [
        {id: 'home',     label: 'Home'},
        {id: 'trending', label: 'Trending'},
        ...(userStorageGet('showLocalTab', '0') === '1' ? [{id: 'local', label: 'Local'}] : []),
        ...(userStorageGet('showFederatedTab', '0') === '1' ? [{id: 'federated', label: 'Federated'}] : []),
        ..._homeLists.map(l => ({id: l.id, label: l.title})),
    ];
    if (!tabs.some(t => t.id === _homeTab)) {
        _homeTab = 'home';
    }
    bar.innerHTML = tabs.map(t =>
        `<button class="ht-tab${_homeTab === t.id ? ' active' : ''}" role="tab"
            aria-selected="${_homeTab === t.id}"
            onclick="showHome('${escJsSq(t.id)}')">${esc(t.label)}</button>`
    ).join('');
    bar.style.display = 'flex';
    document.getElementById('col-header').style.display = 'none';
    // Scroll active tab into view (useful when returning from a thread with a list tab active)
    requestAnimationFrame(() => {
        bar.querySelector('.ht-tab.active')?.scrollIntoView({block: 'nearest', inline: 'nearest', behavior: 'auto'});
    });
}

async function showLocal() {
    setColHeader('Local'); clearContent(); _currentRenderFn = renderStatus;
    addLoadMoreBtn(); await loadFeed('/api/v1/timelines/public', renderStatus);
}

let _notifFilter = 'all';
let _notifLastReadId = '0';
let _notifSeenMaxId = '0';

function notifIdGt(a, b) {
    try { return BigInt(String(a || '0')) > BigInt(String(b || '0')); } catch { return String(a || '0') > String(b || '0'); }
}

function notifIdGte(a, b) {
    try { return BigInt(String(a || '0')) >= BigInt(String(b || '0')); } catch { return String(a || '0') >= String(b || '0'); }
}

async function markNotificationsReadUpTo(lastId) {
    const id = String(lastId || '');
    if (!id || !/^\d+$/.test(id)) return;
    if (notifIdGt(id, _notifLastReadId)) _notifLastReadId = id;
    if (notifIdGt(id, _notifSeenMaxId)) _notifSeenMaxId = id;
    _pendingNotifs = 0;
    updateNotifBadge();
    try {
        await Api.post('/api/v1/markers', {notifications: {last_read_id: id}});
    } catch {}
}

async function showNotifications(filter) {
    if (filter !== undefined) _notifFilter = filter;
    setColHeader('Notifications'); clearContent(); _currentRenderFn = renderNotification;
    if (_notifFilter === 'all') {
        _pendingNotifs = 0;
        updateNotifBadge();
    }
    const content = document.getElementById('col-content');
    // Render notification tabs
    content.insertAdjacentHTML('beforeend', `
        <div class="explore-tabs" style="position:sticky;top:2.9rem;z-index:9">
            <div class="explore-tab${_notifFilter === 'all' ? ' active' : ''}" onclick="showNotifications('all')">All</div>
            <div class="explore-tab${_notifFilter === 'mentions' ? ' active' : ''}" onclick="showNotifications('mentions')">Mentions</div>
        </div>`);
    addLoadMoreBtn();
    const params = _notifFilter === 'mentions' ? {'types[]': 'mention'} : {};
    _currentEndpointParams = params;
    await loadFeed('/api/v1/notifications', renderNotification, params);

    // Only the full notifications view should advance the global read marker.
    if (_notifFilter === 'all') {
        try {
            const latest = await Api.get('/api/v1/notifications', {limit: 1});
            if (latest[0]?.id) {
                await markNotificationsReadUpTo(latest[0].id);
            }
        } catch {}
    }
}

async function showThread(id) {
    setColHeader('Post', true); clearContent();
    window.scrollTo(0, 0); // reset before rendering so getBoundingClientRect is reliable
    const content = document.getElementById('col-content');
    content.innerHTML = skeletonHtml(3);
    try {
        const [s, ctx] = await Promise.all([
            Api.get('/api/v1/statuses/' + id),
            Api.get('/api/v1/statuses/' + id + '/context'),
        ]);
        content.innerHTML = '';
        ctx.ancestors.forEach(a  => content.insertAdjacentHTML('beforeend', renderStatus(a)));
        content.insertAdjacentHTML('beforeend', renderStatus(s, true));
        ctx.descendants.forEach(d => content.insertAdjacentHTML('beforeend', renderStatus(d)));
        // Add thread connector lines between adjacent cards
        const cards = [...content.querySelectorAll('.status-card')];
        const focalIdx = cards.findIndex(c => c.classList.contains('status-focal'));
        // Build parent-child map for descendants
        const descIds = ctx.descendants.map(d => d.id);
        const descMap = {};
        ctx.descendants.forEach(d => { if (d.in_reply_to_id) { descMap[d.in_reply_to_id] = (descMap[d.in_reply_to_id] || 0) + 1; } });
        cards.forEach((card, i) => {
            if (i < focalIdx) { card.classList.add('thread-line-below'); if (i > 0) card.classList.add('thread-line-above'); }
            if (i === focalIdx && focalIdx > 0) card.classList.add('thread-line-above');
            // Descendants: connect direct replies
            if (i > focalIdx) {
                const cid = card.dataset.id;
                const desc = ctx.descendants.find(d => d.id === cid);
                if (desc && desc.in_reply_to_id) {
                    const parentCard = content.querySelector(`.status-card[data-id="${desc.in_reply_to_id}"]`);
                    if (parentCard) parentCard.classList.add('thread-line-below');
                    card.classList.add('thread-line-above');
                }
            }
        });
        const focal = content.querySelector('.status-focal');
        if (focal && focalIdx > 0) {
            // Scroll so focal post sits just below the sticky header.
            // We must re-scroll after ancestor images load because they shift the layout.
            const doScroll = () => {
                const headerH = document.getElementById('col-header')?.offsetHeight ?? 0;
                const top = focal.getBoundingClientRect().top + window.scrollY - headerH - 4;
                window.scrollTo({top: Math.max(0, top), behavior: 'auto'});
            };
            requestAnimationFrame(doScroll);
            // Track unloaded images in ancestor cards; re-scroll once they all settle
            const ancestorImgs = cards.slice(0, focalIdx).flatMap(c => [...c.querySelectorAll('img')]);
            const unloaded = ancestorImgs.filter(img => !img.complete);
            if (unloaded.length) {
                let rem = unloaded.length;
                const onLoad = () => { if (--rem === 0) doScroll(); };
                unloaded.forEach(img => img.addEventListener('load', onLoad, {once: true}));
                setTimeout(doScroll, 800); // fallback if some images never fire load
            }
        }
    } catch (e) {
        content.innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

async function showProfile(id) {
    setColHeader('Profile', true); clearContent();
    const content = document.getElementById('col-content');
    content.innerHTML = skeletonHtml(4);
    try {
        const isOwn = id === WCFG.myId;
        const [account, statuses, rels] = await Promise.all([
            Api.get('/api/v1/accounts/' + id),
            Api.get('/api/v1/accounts/' + id + '/statuses', {limit: 20, exclude_replies: true, exclude_reblogs: false}),
            isOwn ? Promise.resolve([null]) : Api.get('/api/v1/accounts/relationships', {'id[]': id}),
        ]);
        content.innerHTML = renderProfileHeader(account, rels[0]);
        _currentRenderFn = renderStatus;
        _maxId = statuses.length ? statuses[statuses.length - 1].id : null;
        _currentEndpoint = '/api/v1/accounts/' + id + '/statuses';
        _currentEndpointParams = {exclude_replies: true, exclude_reblogs: false};
        statuses.forEach(s => content.insertAdjacentHTML('beforeend', renderStatus(s)));
        if (statuses.length === 20) addLoadMoreBtn();
    } catch (e) {
        content.innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

async function switchProfileTab(id, tab, btn) {
    // Update active tab
    btn.closest('.profile-tabs').querySelectorAll('.profile-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    // Remove existing posts below profile header
    const content = document.getElementById('col-content');
    const header = content.querySelector('.profile-header');
    while (header && header.nextSibling) header.nextSibling.remove();
    content.insertAdjacentHTML('beforeend', skeletonHtml(3));
    // Build endpoint params
    let params = {limit: 20};
    if (tab === 'posts')   { params.exclude_replies = true; params.exclude_reblogs = false; }
    if (tab === 'replies') { params.exclude_replies = false; params.exclude_reblogs = true; }
    if (tab === 'media')   { params.only_media = true; }
    const ep = tab === 'likes'
        ? '/api/v1/favourites'
        : '/api/v1/accounts/' + id + '/statuses';
    try {
        const statuses = await Api.get(ep, params);
        // Clear skeletons
        while (header && header.nextSibling) header.nextSibling.remove();
        _currentRenderFn = renderStatus;
        _maxId = statuses.length ? statuses[statuses.length - 1].id : null;
        _currentEndpoint = ep;
        _currentEndpointParams = tab === 'likes' ? {} : params;
        statuses.forEach(s => content.insertAdjacentHTML('beforeend', renderStatus(s)));
        if (!statuses.length) content.insertAdjacentHTML('beforeend', '<div class="feed-end">No posts.</div>');
        else if (statuses.length >= 20) addLoadMoreBtn();
    } catch (e) {
        while (header && header.nextSibling) header.nextSibling.remove();
        content.insertAdjacentHTML('beforeend', '<div class="feed-error">Error: ' + esc(e.message) + '</div>');
    }
}

async function showSearch() {
    setColHeader('Search'); clearContent();
    document.getElementById('col-content').innerHTML = `
        <div class="search-box">
            <input type="search" id="search-input" placeholder="Search accounts, posts, hashtags..." autocomplete="off">
            <button onclick="doSearch()">Search</button>
        </div>
        <div id="search-results"></div>`;
    document.getElementById('search-input').focus();
    document.getElementById('search-input').addEventListener('keydown', e => { if (e.key === 'Enter') { clearTimeout(_searchDebounce); doSearch(); } });
    document.getElementById('search-input').addEventListener('input', e => {
        clearTimeout(_searchDebounce);
        const q = e.target.value.trim();
        if (q.length > 1) {
            _searchDebounce = setTimeout(doSearch, 450);
            return;
        }
        _searchReqSeq++;
        const res = document.getElementById('search-results');
        if (res) res.innerHTML = q ? '' : '<div class="feed-end">Type at least 2 characters.</div>';
    });
}

async function doSearch() {
    const q = document.getElementById('search-input')?.value?.trim();
    if (!q) return;
    const res = document.getElementById('search-results');
    if (!res) return;
    const reqId = ++_searchReqSeq;
    res.innerHTML = '<div class="feed-loading">Searching...</div>';
    try {
        const r = await Api.get('/api/v2/search', {q, resolve: true, limit: 10});
        if (reqId !== _searchReqSeq) return;
        let html = '';
        if (r.accounts?.length)  { html += '<div class="search-section-title">Accounts</div>';   r.accounts.forEach(a  => html += renderAccount(a)); }
        if (r.statuses?.length)  { html += '<div class="search-section-title">Posts</div>';      r.statuses.forEach(s  => html += renderStatus(s)); }
        if (r.hashtags?.length)  { html += '<div class="search-section-title">Hashtags</div>';    r.hashtags.forEach(h  => html += `<div class="hashtag-item"><a href="#" onclick="searchTag('${escJsSq(h.name)}')">#${esc(h.name)}</a></div>`); }
        if (!html) html = '<div class="feed-end">No results.</div>';
        res.innerHTML = html;
    } catch (e) {
        if (reqId !== _searchReqSeq) return;
        res.innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

async function loadRightCol() {
    const trendEl = document.getElementById('right-trending');
    if (!trendEl) return;

    // Trending tags
    const trends = await Api.get('/api/v1/trends/tags', {limit: 5}).catch(() => []);
    if (trends.length) {
        trendEl.insertAdjacentHTML('beforeend', `<div class="right-card"><div class="right-card-title">Trending</div>`
            + trends.map(t => {
                const uses = (t.history ?? []).reduce((s, h) => s + parseInt(h.uses ?? 0), 0);
                return `<div class="right-trend-item" onclick="navigate('TAG_TIMELINE','${escJsSq(t.name)}')">
                    <span class="right-trend-tag">#${esc(t.name)}</span>
                    <span class="right-trend-count">${uses} posts</span>
                </div>`;
            }).join('') + `</div>`);
    }

}

async function toggleRightFollow(btn) {
    const id        = btn.dataset.accountId;
    const following = btn.dataset.following === '1';
    btn.disabled = true;
    try {
        const r = await Api.post('/api/v1/accounts/' + id + (following ? '/unfollow' : '/follow'), {});
        const now = !!r.following;
        const requested = !!r.requested && !now;
        btn.dataset.following  = now ? '1' : '0';
        btn.dataset.requested  = requested ? '1' : '0';
        btn.textContent        = now ? 'Following' : (requested ? 'Requested' : 'Follow');
        btn.classList.toggle('following', now || requested);
    } catch (e) { Toast.err('Error: ' + e.message); }
    btn.disabled = false;
}

function searchTag(tag) {
    navigate('TAG_TIMELINE', tag);
}

function syncRightSearchInput(value) {
    const input = document.getElementById('right-search-input');
    if (!input) return;
    if (document.activeElement !== input) {
        input.value = value || '';
    }
}

function openExploreSearch(query) {
    _pendingExploreQuery = (query || '').trim();
    navigate('EXPLORE');
}

// ── New views ───────────────────────────────────────────────────────────────
async function showConversations() {
    setColHeader('Conversations'); clearContent(); _currentRenderFn = renderConversation;
    addLoadMoreBtn();
    await loadFeed('/api/v1/conversations', renderConversation);
}

function renderConversation(conv) {
    const others = conv.accounts.filter(a => a.id !== WCFG.myId);
    const acct   = others[0] ?? conv.accounts[0];
    if (!acct) return '';
    const names   = others.length
        ? others.map(a => esc(a.display_name || a.username)).join(', ')
        : esc(acct.display_name || acct.username);
    const preview = conv.last_status
        ? (conv.last_status.spoiler_text || conv.last_status.content.replace(/<[^>]+>/g, '')).trim().slice(0, 100)
        : '';
    const time = conv.last_status ? timeAgo(conv.last_status.created_at) : '';
    return `
    <div class="conv-card" onclick="navigate('THREAD','${escJsSq(conv.last_status?.id ?? conv.id)}')">
        <div class="conv-avatar-wrap">
            <img class="avatar" src="${esc(acct.avatar)}" alt="" loading="lazy">
            ${conv.unread ? '<span class="conv-unread-dot"></span>' : ''}
        </div>
        <div class="conv-body">
            <div class="conv-header">
                <span class="conv-name">${names}</span>
                <span class="conv-time">${esc(time)}</span>
            </div>
            <div class="conv-preview${conv.unread ? ' unread' : ''}">${esc(preview)}</div>
        </div>
    </div>`;
}

async function showSettings() {
    setColHeader('Settings'); clearContent();
    const col = document.getElementById('col-content');

    const localTabOn = userStorageGet('showLocalTab', '0') === '1';
    const federatedTabOn = userStorageGet('showFederatedTab', '0') === '1';
    const defaultHomeTab = userStorageGet('defaultHomeTab', 'home') || 'home';

    let account = null;
    let prefs = {};
    let notifPolicy = null;
    let mutedAccounts = [];
    let blockedAccounts = [];
    let blockedDomains = [];
    let filters = [];
    let sessions = [];
    let aliases = [];
    let developer = {apps: [], tokens: []};
    try { account = await Api.get('/api/v1/accounts/verify_credentials'); } catch {}
    try { prefs = await Api.get('/api/v1/preferences'); } catch {}
    try { notifPolicy = await Api.get('/api/v1/notifications/policy'); } catch {}
    try { mutedAccounts = await Api.get('/api/v1/mutes'); } catch {}
    try { blockedAccounts = await Api.get('/api/v1/blocks'); } catch {}
    try { blockedDomains = await Api.get('/api/v1/domain_blocks'); } catch {}
    try { filters = await Api.get('/api/v1/filters'); } catch {}
    try { sessions = await Api.get('/api/v1/sessions'); } catch {}
    try { aliases = await Api.get('/api/v1/accounts/aliases'); } catch {}
    try { developer = await Api.get('/api/v1/developer/apps'); } catch {}
    const defVis = prefs['posting:default:visibility'] ?? 'public';
    const defSensitive = prefBool(prefs['posting:default:sensitive']);
    const defLanguage = prefs['posting:default:language'] ?? '';
    const defExpireAfter = Number(prefs['posting:default:expire_after'] ?? 0);
    const readingExpandMedia = prefs['reading:expand:media'] ?? 'default';
    const readingExpandSpoilers = prefBool(prefs['reading:expand:spoilers']);
    const readingAutoplayGifs = prefBool(prefs['reading:autoplay:gifs']);
    const isLocked = prefBool(account?.locked);
    const isDiscoverable = prefBool(account?.discoverable);
    const isIndexable = !prefBool(account?.noindex);
    const webSessions = sessions.filter(session => (session.app_name || '') === 'Web Client');
    const authorizedApps = sessions.filter(session => (session.app_name || '') !== 'Web Client');

    const visOpts = ['public','unlisted','private','direct']
        .map(v => `<option value="${v}"${defVis===v?' selected':''}>${{public:'🌐 Public',unlisted:'🔒 Unlisted',private:'👥 Followers only',direct:'✉️ Direct'}[v]}</option>`)
        .join('');
    const expireOpts = [
        {value:'', label:'Keep permanently'},
        {value:'3600', label:'Delete after 1 hour'},
        {value:'21600', label:'Delete after 6 hours'},
        {value:'86400', label:'Delete after 1 day'},
        {value:'604800', label:'Delete after 7 days'},
        {value:'2592000', label:'Delete after 30 days'},
    ].map(opt => `<option value="${opt.value}"${String(defExpireAfter || '')===opt.value?' selected':''}>${opt.label}</option>`).join('');
    const readingMediaOpts = ['default', 'show_all', 'hide_all']
        .map(v => `<option value="${v}"${readingExpandMedia===v?' selected':''}>${({default:'Default',show_all:'Expand all media',hide_all:'Hide media by default'})[v]}</option>`)
        .join('');
    const defaultHomeOpts = ['home', 'trending', 'local', 'federated']
        .map(v => `<option value="${v}"${defaultHomeTab===v?' selected':''}>${({home:'Home',trending:'Trending',local:'Local',federated:'Federated'})[v]}</option>`)
        .join('');
    const policySelect = (id, value) => `
        <select id="${id}" class="settings-select">
            <option value="accept"${value==='accept'?' selected':''}>Allow</option>
            <option value="filter"${value==='filter'?' selected':''}>Filter</option>
        </select>`;
    const accountChip = (acct, mode) => `<div class="settings-chip-row">
        <div>
            <div class="settings-label" style="color:var(--text);font-weight:700">${esc(acct.display_name || acct.username)}</div>
            <div class="settings-label">@${esc(acct.acct || acct.username)}</div>
        </div>
        <button class="settings-chip-remove" type="button" onclick="${mode === 'mute' ? `removeMutedAccount('${escJsSq(acct.id)}')` : `removeBlockedAccount('${escJsSq(acct.id)}')`}">
            ${mode === 'mute' ? 'Unmute' : 'Unblock'}
        </button>
    </div>`;
    const domainRows = blockedDomains.length
        ? blockedDomains.map(domain => `<div class="settings-chip-row">
            <div class="settings-label" style="color:var(--text)">${esc(domain)}</div>
            <button class="settings-chip-remove" type="button" onclick="removeDomainBlock('${escJsSq(domain)}')">Remove</button>
        </div>`).join('')
        : '<div class="settings-empty">No blocked domains.</div>';
    const filterRows = filters.length
        ? filters.map(filter => {
            const kws = (filter.keywords || []).map(k => k.keyword).join(', ');
            const contexts = (filter.context || []).join(', ');
            const ww = (filter.keywords || []).some(k => k.whole_word);
            return `<div class="settings-panel">
                <div class="settings-panel-head">
                    <div style="min-width:0;flex:1">
                        <div class="settings-panel-title">${esc(filter.title || kws || 'Filter')}</div>
                        <div class="settings-panel-meta">${esc(kws || 'No keywords')}</div>
                        <div class="settings-panel-meta">Action: ${esc(filter.filter_action || 'warn')} · Context: ${esc(contexts || 'home')}</div>
                        <div class="settings-pill-row">${ww ? '<span class="settings-pill">Whole-word matching</span>' : ''}</div>
                    </div>
                    <div style="display:flex;flex-direction:column;gap:.5rem;align-items:flex-end">
                        <button class="settings-chip-remove" type="button" onclick="loadFilterIntoForm('${escJsSq(filter.id)}')">Edit</button>
                        <button class="settings-chip-remove" type="button" onclick="removeFilter('${escJsSq(filter.id)}')">Delete</button>
                    </div>
                </div>
            </div>`;
        }).join('')
        : '<div class="settings-empty">No keyword filters.</div>';
    const webSessionRows = webSessions.length
        ? webSessions.map(session => `<div class="settings-panel">
            <div class="settings-panel-head">
                <div style="min-width:0;flex:1">
                    <div class="settings-panel-title">${esc(session.app_name || 'Web Client')}${session.current ? ' · Current session' : ''}</div>
                    <div class="settings-panel-meta">${esc(session.token_hint || '')}</div>
                    <div class="settings-panel-meta">Created ${esc(timeAgo(session.created_at))}${session.last_used_at ? ' · Active ' + esc(timeAgo(session.last_used_at)) : ''}</div>
                    ${session.app_website ? `<div class="settings-panel-meta">${esc(session.app_website)}</div>` : ''}
                    <div class="settings-pill-row">${(session.scopes || []).map(scope => `<span class="settings-pill">${esc(scope)}</span>`).join('')}</div>
                </div>
                ${session.current
                    ? `<button class="settings-chip-remove danger" type="button" onclick="revokeCurrentSession()">Sign out</button>`
                    : `<button class="settings-chip-remove" type="button" onclick="revokeSession('${escJsSq(session.id)}')">Revoke</button>`}
            </div>
        </div>`).join('')
        : '<div class="settings-empty">No active web sessions.</div>';
    const authorizedAppRows = authorizedApps.length
        ? authorizedApps.map(session => `<div class="settings-panel">
            <div class="settings-panel-head">
                <div style="min-width:0;flex:1">
                    <div class="settings-panel-title">${esc(session.app_name || 'Authorized application')}</div>
                    <div class="settings-panel-meta">${esc(session.token_hint || '')}</div>
                    <div class="settings-panel-meta">Created ${esc(timeAgo(session.created_at))}${session.last_used_at ? ' · Active ' + esc(timeAgo(session.last_used_at)) : ''}</div>
                    ${session.app_website ? `<div class="settings-panel-meta">${esc(session.app_website)}</div>` : ''}
                    <div class="settings-pill-row">${(session.scopes || []).map(scope => `<span class="settings-pill">${esc(scope)}</span>`).join('')}</div>
                </div>
                <button class="settings-chip-remove" type="button" onclick="revokeSession('${escJsSq(session.id)}')">Revoke</button>
            </div>
        </div>`).join('')
        : '<div class="settings-empty">No authorized applications.</div>';
    const aliasRows = aliases.length
        ? aliases.map(acct => `<div class="settings-chip-row">
            <div>
                <div class="settings-label" style="color:var(--text);font-weight:700">${esc(acct.display_name || acct.username)}</div>
                <div class="settings-label">@${esc(acct.acct || acct.username)}</div>
            </div>
            <button class="settings-chip-remove" type="button" onclick="removeMigrationAlias('${escJsSq(acct.acct || '')}')">Remove</button>
        </div>`).join('')
        : '<div class="settings-empty">No migration aliases.</div>';
    const developerAppRows = developer.apps?.length
        ? developer.apps.map(app => `<div class="settings-panel">
            <div class="settings-panel-head">
                <div style="min-width:0;flex:1">
                    <div class="settings-panel-title">${esc(app.name)}</div>
                    <div class="settings-panel-meta">Redirect URI: ${esc(app.redirect_uri || 'urn:ietf:wg:oauth:2.0:oob')}</div>
                    ${app.website ? `<div class="settings-panel-meta">${esc(app.website)}</div>` : ''}
                    <div class="settings-pill-row">${(app.scopes || []).map(scope => `<span class="settings-pill">${esc(scope)}</span>`).join('')}</div>
                    <div class="settings-secret"><strong>Client ID</strong><br>${esc(app.client_id || '')}</div>
                    <div class="settings-secret"><strong>Client secret</strong><br>${esc(app.client_secret || '')}</div>
                </div>
                <div style="display:flex;flex-direction:column;gap:.5rem;align-items:flex-end">
                    <button class="settings-chip-remove" type="button" onclick="copyDeveloperSecret('${escJsSq(app.client_id || '')}','Client ID copied.')">Copy ID</button>
                    <button class="settings-chip-remove" type="button" onclick="copyDeveloperSecret('${escJsSq(app.client_secret || '')}','Client secret copied.')">Copy secret</button>
                    <button class="settings-chip-remove" type="button" onclick="prefillDeveloperTokenForm('${escJsSq(app.id)}')">New token</button>
                    <button class="settings-chip-remove danger" type="button" onclick="deleteDeveloperApp('${escJsSq(app.id)}')">Delete app</button>
                </div>
            </div>
        </div>`).join('')
        : '<div class="settings-empty">No developer applications yet.</div>';
    const developerTokenRows = developer.tokens?.length
        ? developer.tokens.map(token => `<div class="settings-panel">
            <div class="settings-panel-head">
                <div style="min-width:0;flex:1">
                    <div class="settings-panel-title">${esc(token.app_name || 'Application token')}</div>
                    <div class="settings-panel-meta">${esc(token.token_hint || '')}</div>
                    <div class="settings-panel-meta">Created ${esc(timeAgo(token.created_at))}${token.last_used_at ? ' · Active ' + esc(timeAgo(token.last_used_at)) : ''}</div>
                    <div class="settings-pill-row">${(token.scopes || []).map(scope => `<span class="settings-pill">${esc(scope)}</span>`).join('')}</div>
                </div>
                <button class="settings-chip-remove danger" type="button" onclick="revokeDeveloperToken('${escJsSq(token.id)}')">Revoke</button>
            </div>
        </div>`).join('')
        : '<div class="settings-empty">No personal access tokens created here.</div>';

    col.innerHTML = `
    <div class="settings-section">
        <h2 class="settings-title">Profile</h2>
        <div class="settings-row">
            <div>
                <div class="settings-label" style="color:var(--text);font-weight:700">${esc(account?.display_name || WCFG.myDisplayName || WCFG.myUsername)}</div>
                <div class="settings-label">@${esc(account?.acct || WCFG.myUsername)}</div>
            </div>
            <div style="display:flex;gap:.6rem;flex-wrap:wrap;justify-content:flex-end">
                <button class="settings-save-btn" type="button" onclick="navigate('EDIT_PROFILE')" style="margin-top:0">Edit profile</button>
                <button class="settings-save-btn" type="button" onclick="navigate('PROFILE', WCFG.myId)" style="margin-top:0;background:transparent;color:var(--blue);border:1px solid var(--border)">View profile</button>
            </div>
        </div>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Appearance</h2>
        <div class="settings-row">
            <label class="settings-label">Theme</label>
            <select id="set-appearance-theme" class="settings-select">
                <option value="system"${APP_APPEARANCE.theme==='system'?' selected':''}>System</option>
                <option value="light"${APP_APPEARANCE.theme==='light'?' selected':''}>Light</option>
                <option value="dark"${APP_APPEARANCE.theme==='dark'?' selected':''}>Dark</option>
            </select>
        </div>
        <div class="settings-row">
            <label class="settings-label">Density</label>
            <select id="set-appearance-density" class="settings-select">
                <option value="comfortable"${APP_APPEARANCE.density==='comfortable'?' selected':''}>Comfortable</option>
                <option value="compact"${APP_APPEARANCE.density==='compact'?' selected':''}>Compact</option>
            </select>
        </div>
        <div class="settings-row">
            <label class="settings-label">Column width</label>
            <select id="set-appearance-width" class="settings-select">
                <option value="narrow"${APP_APPEARANCE.width==='narrow'?' selected':''}>Narrow</option>
                <option value="default"${APP_APPEARANCE.width==='default'?' selected':''}>Default</option>
                <option value="wide"${APP_APPEARANCE.width==='wide'?' selected':''}>Wide</option>
            </select>
        </div>
        <div class="settings-row">
            <label class="settings-label">Text size</label>
            <select id="set-appearance-text-size" class="settings-select">
                <option value="small"${APP_APPEARANCE.textSize==='small'?' selected':''}>Small</option>
                <option value="default"${APP_APPEARANCE.textSize==='default'?' selected':''}>Default</option>
                <option value="large"${APP_APPEARANCE.textSize==='large'?' selected':''}>Large</option>
            </select>
        </div>
        <button class="settings-save-btn" onclick="saveAppearanceSettings()">Save appearance</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Posting defaults</h2>
        <div class="settings-row">
            <label class="settings-label">Default visibility</label>
            <select id="set-vis" class="settings-select">${visOpts}</select>
        </div>
        <div class="settings-row">
            <label class="settings-label">Default language</label>
            <input type="text" id="set-language" class="settings-input" value="${esc(defLanguage)}" placeholder="en" maxlength="12" spellcheck="false">
        </div>
        <div class="settings-row">
            <label class="settings-label">Auto-delete posts after</label>
            <select id="set-expire-after" class="settings-select">${expireOpts}</select>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Mark media as sensitive by default</label>
            <button id="set-sensitive" class="toggle-btn${defSensitive ? ' on' : ''}" type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <button class="settings-save-btn" onclick="savePostingSettings()">Save posting defaults</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Home and timeline tabs</h2>
        <div class="settings-row">
            <label class="settings-label">Default home tab</label>
            <select id="set-default-home-tab" class="settings-select">${defaultHomeOpts}</select>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Show Local tab</label>
            <button id="set-local-tab" class="toggle-btn${localTabOn ? ' on' : ''}"
                type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Show Federated tab</label>
            <button id="set-federated-tab" class="toggle-btn${federatedTabOn ? ' on' : ''}"
                type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <button class="settings-save-btn" onclick="saveTimelineSettings()">Save timeline tabs</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Reading</h2>
        <div class="settings-row">
            <label class="settings-label">Media expansion</label>
            <select id="set-expand-media" class="settings-select">${readingMediaOpts}</select>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Expand content warnings by default</label>
            <button id="set-expand-spoilers" class="toggle-btn${readingExpandSpoilers ? ' on' : ''}" type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Autoplay GIF/video previews</label>
            <button id="set-autoplay-gifs" class="toggle-btn${readingAutoplayGifs ? ' on' : ''}" type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <button class="settings-save-btn" onclick="saveReadingSettings()">Save reading settings</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Notifications</h2>
        <div class="settings-row">
            <label class="settings-label">People you do not follow</label>
            ${policySelect('notif-not-following', notifPolicy?.for_not_following || 'accept')}
        </div>
        <div class="settings-row">
            <label class="settings-label">People who do not follow you</label>
            ${policySelect('notif-not-followers', notifPolicy?.for_not_followers || 'accept')}
        </div>
        <div class="settings-row">
            <label class="settings-label">New accounts</label>
            ${policySelect('notif-new-accounts', notifPolicy?.for_new_accounts || 'accept')}
        </div>
        <div class="settings-row">
            <label class="settings-label">Private mentions</label>
            ${policySelect('notif-private-mentions', notifPolicy?.for_private_mentions || 'accept')}
        </div>
        <div class="settings-row">
            <label class="settings-label">Limited accounts</label>
            ${policySelect('notif-limited-accounts', notifPolicy?.for_limited_accounts || 'accept')}
        </div>
        <div class="settings-row">
            <span class="settings-label">Pending filtered notifications</span>
            <span class="settings-label" style="color:var(--text)">${esc(notifPolicy?.summary?.pending_notifications_count ?? 0)}</span>
        </div>
        <button class="settings-save-btn" onclick="saveNotificationSettings()">Save notification settings</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Privacy and reach</h2>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Require follow approval</label>
            <button id="set-locked" class="toggle-btn${isLocked ? ' on' : ''}" type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Show in profile suggestions</label>
            <button id="set-discoverable" class="toggle-btn${isDiscoverable ? ' on' : ''}" type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Allow search engine indexing</label>
            <button id="set-indexable" class="toggle-btn${isIndexable ? ' on' : ''}" type="button" onclick="this.classList.toggle('on')">
                <span class="toggle-knob"></span>
            </button>
        </div>
        <button class="settings-save-btn" onclick="savePrivacySettings()">Save privacy settings</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Filters and mutes</h2>
        <div class="settings-row">
            <label class="settings-label">Mute or block account</label>
            <input type="text" id="set-account-acct" class="settings-input" placeholder="@name@server.tld or name@server.tld" spellcheck="false">
        </div>
        <div class="settings-actions-row">
            <button class="settings-save-btn" type="button" onclick="addAccountRestriction('mute')">Mute account</button>
            <button class="settings-save-btn" type="button" onclick="addAccountRestriction('block')" style="background:transparent;color:var(--red,#EC4040);border:1px solid var(--border)">Block account</button>
        </div>
        <div class="settings-subtitle">Muted accounts</div>
        <div id="settings-muted-list">${mutedAccounts.length ? mutedAccounts.map(acct => accountChip(acct, 'mute')).join('') : '<div class="settings-empty">No muted accounts.</div>'}</div>
        <div class="settings-subtitle">Blocked accounts</div>
        <div id="settings-blocked-list">${blockedAccounts.length ? blockedAccounts.map(acct => accountChip(acct, 'block')).join('') : '<div class="settings-empty">No blocked accounts.</div>'}</div>
        <div class="settings-subtitle">Blocked domains</div>
        <div class="settings-row">
            <label class="settings-label">Domain</label>
            <input type="text" id="set-domain-block" class="settings-input" placeholder="example.org" spellcheck="false">
        </div>
        <button class="settings-save-btn" type="button" onclick="addDomainBlock()">Block domain</button>
        <div id="settings-domain-blocks">${domainRows}</div>
        <div class="settings-subtitle">Keyword filters</div>
        <div class="settings-row">
            <label class="settings-label">Title</label>
            <input type="text" id="set-filter-title" class="settings-input" placeholder="Muted words" maxlength="80">
        </div>
        <div class="settings-row">
            <label class="settings-label">Keyword</label>
            <input type="text" id="set-filter-keyword" class="settings-input" placeholder="keyword or phrase, comma-separated" maxlength="240">
        </div>
        <div class="settings-row">
            <label class="settings-label">Action</label>
            <select id="set-filter-action" class="settings-select">
                <option value="warn">Warn</option>
                <option value="hide">Hide</option>
            </select>
        </div>
        <div class="settings-row" style="justify-content:space-between;align-items:center">
            <label class="settings-label" style="margin:0">Whole-word matching</label>
            <button id="set-filter-whole-word" class="toggle-btn" type="button" onclick="this.classList.toggle('on')"><span class="toggle-knob"></span></button>
        </div>
        <div class="settings-row">
            <label class="settings-label">Contexts</label>
            <div class="settings-check-grid">
                <label><input type="checkbox" name="set-filter-context" value="home" checked> Home</label>
                <label><input type="checkbox" name="set-filter-context" value="notifications" checked> Notifications</label>
                <label><input type="checkbox" name="set-filter-context" value="public"> Public</label>
                <label><input type="checkbox" name="set-filter-context" value="thread"> Threads</label>
                <label><input type="checkbox" name="set-filter-context" value="account"> Profiles</label>
            </div>
        </div>
        <input type="hidden" id="set-filter-id" value="">
        <div class="settings-actions-row">
            <button class="settings-save-btn" type="button" onclick="saveKeywordFilter()">Save filter</button>
            <button class="settings-save-btn" type="button" onclick="resetFilterForm()" style="background:transparent;color:var(--blue);border:1px solid var(--border)">Clear form</button>
        </div>
        <div id="settings-filters">${filterRows}</div>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Authorized applications and sessions</h2>
        <div class="settings-helper">This is access already granted to your account. Revoke old browser sessions separately from third-party application access.</div>
        <div class="settings-subtitle">Web sessions</div>
        <div id="settings-sessions">${webSessionRows}</div>
        <button class="settings-save-btn" type="button" onclick="revokeOtherSessions()">Sign out other sessions</button>
        <div class="settings-subtitle">Authorized applications</div>
        <div id="settings-authorized-apps">${authorizedAppRows}</div>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Developer applications</h2>
        <div class="settings-helper">Create OAuth applications for bots, scripts and integrations. These are apps you own, not just apps already authorized to access your account.</div>
        <div class="settings-subtitle">Create application</div>
        <div class="settings-row">
            <label class="settings-label">Application name</label>
            <input type="text" id="dev-app-name" class="settings-input" placeholder="Starling Bot" maxlength="100">
        </div>
        <div class="settings-row">
            <label class="settings-label">Website</label>
            <input type="text" id="dev-app-website" class="settings-input" placeholder="https://example.org" maxlength="255" spellcheck="false">
        </div>
        <div class="settings-row">
            <label class="settings-label">Redirect URI</label>
            <input type="text" id="dev-app-redirect" class="settings-input" value="urn:ietf:wg:oauth:2.0:oob" maxlength="500" spellcheck="false">
        </div>
        <div class="settings-helper">Use <code>urn:ietf:wg:oauth:2.0:oob</code> for scripts and manual setups, or a real callback URL for external apps.</div>
        <div class="settings-row">
            <label class="settings-label">Scopes</label>
            <div class="settings-check-grid">
                <label><input type="checkbox" name="dev-app-scope" value="read" checked> Read</label>
                <label><input type="checkbox" name="dev-app-scope" value="write" checked> Write</label>
                <label><input type="checkbox" name="dev-app-scope" value="follow" checked> Follow</label>
                <label><input type="checkbox" name="dev-app-scope" value="push"> Push</label>
            </div>
        </div>
        <button class="settings-save-btn" type="button" onclick="createDeveloperApp()">Create application</button>
        <div class="settings-subtitle">Your applications</div>
        <div id="settings-developer-apps">${developerAppRows}</div>
        <div class="settings-subtitle">Personal access tokens</div>
        <div class="settings-row">
            <label class="settings-label">Application</label>
            <select id="dev-token-app" class="settings-select">
                <option value="">Choose an application</option>
                ${(developer.apps || []).map(app => `<option value="${esc(app.id)}">${esc(app.name)}</option>`).join('')}
            </select>
        </div>
        <div class="settings-row">
            <label class="settings-label">Token scopes</label>
            <div class="settings-checkbox-grid">
                <label><input type="checkbox" name="dev-token-scope" value="read" checked> Read</label>
                <label><input type="checkbox" name="dev-token-scope" value="write" checked> Write</label>
                <label><input type="checkbox" name="dev-token-scope" value="follow" checked> Follow</label>
                <label><input type="checkbox" name="dev-token-scope" value="push"> Push</label>
            </div>
        </div>
        <button class="settings-save-btn" type="button" onclick="createPersonalAccessToken()">Create personal access token</button>
        <div class="settings-token-box" id="settings-dev-token-once" style="display:none">
            <strong>Copy this token now. It will only be shown once.</strong>
            <code id="settings-dev-token-value"></code>
            <div class="settings-helper">Example: publish a post from your terminal with this token.</div>
            <pre id="settings-dev-curl-value"></pre>
            <div class="settings-actions-row" style="margin-top:.75rem;margin-bottom:0">
                <button class="settings-chip-remove" type="button" onclick="copyTokenFromSettings()">Copy token</button>
                <button class="settings-chip-remove" type="button" onclick="copyDeveloperCurlExample()">Copy curl example</button>
                <button class="settings-chip-remove" type="button" onclick="hideDeveloperTokenBox()">Hide</button>
            </div>
        </div>
        <div id="settings-developer-tokens">${developerTokenRows}</div>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Import and export</h2>
        <div class="settings-subtitle">Export CSV</div>
        <div class="settings-actions-row">
            <button class="settings-save-btn" type="button" onclick="exportFollowCsv('following')">Export following CSV</button>
            <button class="settings-save-btn" type="button" onclick="exportFollowCsv('followers')" style="background:transparent;color:var(--blue);border:1px solid var(--border)">Export followers CSV</button>
        </div>
        <div class="settings-empty">Follower CSV export is informational. Import supports following lists only.</div>
        <div class="settings-subtitle">Import following CSV</div>
        <div class="settings-row">
            <label class="settings-label">CSV file</label>
            <input type="file" id="set-following-import" class="settings-input" accept=".csv,text/csv">
        </div>
        <button class="settings-save-btn" type="button" onclick="importFollowingCsv()">Import following CSV</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Account migration</h2>
        <div class="settings-subtitle">Migrate from a different account</div>
        <div class="settings-row">
            <label class="settings-label">Old account alias</label>
            <input type="text" id="set-migration-alias" class="settings-input" placeholder="oldname@oldserver.tld" spellcheck="false">
        </div>
        <button class="settings-save-btn" type="button" onclick="addMigrationAlias()">Add alias</button>
        <div id="settings-aliases">${aliasRows}</div>
        <div class="settings-subtitle">Move to a different account</div>
        <div class="settings-row">
            <label class="settings-label">New account</label>
            <input type="text" id="set-move-acct" class="settings-input" placeholder="newname@newserver.tld" spellcheck="false">
        </div>
        <div class="settings-row">
            <label class="settings-label">Current password</label>
            <input type="password" id="set-move-password" class="settings-input" autocomplete="current-password">
        </div>
        <button class="settings-save-btn" type="button" onclick="moveToDifferentAccount()">Move account</button>
    </div>
    <div class="settings-section">
        <h2 class="settings-title">Account security</h2>
        <div class="settings-row">
            <label class="settings-label">Current password</label>
            <input type="password" id="set-pw-cur" class="settings-input" autocomplete="current-password">
        </div>
        <div class="settings-row">
            <label class="settings-label">New password</label>
            <input type="password" id="set-pw-new" class="settings-input" autocomplete="new-password">
        </div>
        <div class="settings-row">
            <label class="settings-label">Confirm password</label>
            <input type="password" id="set-pw-cfm" class="settings-input" autocomplete="new-password">
        </div>
        <button class="settings-save-btn" onclick="savePassword()">Change password</button>
        <form method="post" action="/web/logout" style="margin-top:1rem">
            <input type="hidden" name="csrf" value="${esc(WCFG.webCsrf||'')}">
            <button type="submit" class="settings-save-btn" style="width:100%;background:transparent;color:var(--red, #EC4040);border:1px solid var(--border)">Sign out</button>
        </form>
        <div class="settings-subtitle">Delete account</div>
        <div class="settings-row">
            <label class="settings-label">Confirm password</label>
            <input type="password" id="set-delete-password" class="settings-input" autocomplete="current-password">
        </div>
        <button class="settings-save-btn" type="button" onclick="deleteOwnAccount()" style="width:100%;background:transparent;color:var(--red,#EC4040);border:1px solid var(--border)">Delete account permanently</button>
    </div>
    ${WCFG.isAdmin ? `
    <div class="settings-section">
        <h2 class="settings-title">Administration</h2>
        <div class="settings-row">
            <span class="settings-label">Server administration panel</span>
        </div>
        <form method="post" action="/web/admin-sso" style="margin:0">
            <input type="hidden" name="csrf" value="${esc(WCFG.webCsrf||'')}">
            <button type="submit" class="settings-save-btn" style="width:100%">
                Open administration panel ↗
            </button>
        </form>
    </div>` : ''}`;
    setupSettingsTabs();
}

async function savePostingSettings() {
    const vis = document.getElementById('set-vis')?.value;
    const sensitive = document.getElementById('set-sensitive')?.classList.contains('on') || false;
    const language = (document.getElementById('set-language')?.value || '').trim().toLowerCase();
    const expireAfter = Number(document.getElementById('set-expire-after')?.value || 0);
    if (!vis) return;
    try {
        await Api.patch('/api/v1/accounts/update_credentials', {
            source: {
                privacy: vis,
                sensitive,
                language: language || null,
                expire_after: expireAfter > 0 ? expireAfter : null,
            },
        });
        USERPREFS.defaultVisibility = vis;
        USERPREFS.defaultSensitive = sensitive;
        USERPREFS.defaultLanguage = language || null;
        USERPREFS.defaultExpireAfter = expireAfter > 0 ? expireAfter : null;
        Toast.ok('Posting defaults saved.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

function saveTimelineSettings() {
    const showLocal = document.getElementById('set-local-tab')?.classList.contains('on') ? '1' : '0';
    const showFederated = document.getElementById('set-federated-tab')?.classList.contains('on') ? '1' : '0';
    let defaultHomeTab = document.getElementById('set-default-home-tab')?.value || 'home';
    if ((defaultHomeTab === 'local' && showLocal !== '1') || (defaultHomeTab === 'federated' && showFederated !== '1')) {
        defaultHomeTab = 'home';
    }
    userStorageSet('showLocalTab', showLocal);
    userStorageSet('showFederatedTab', showFederated);
    userStorageSet('defaultHomeTab', defaultHomeTab);

    if ((_homeTab === 'local' && showLocal !== '1') || (_homeTab === 'federated' && showFederated !== '1')) {
        _homeTab = 'home';
    }
    if (WCFG.view === 'HOME') {
        showHome(_homeTab);
    }
    Toast.ok('Timeline tabs saved.');
}

function saveAppearanceSettings() {
    APP_APPEARANCE.theme = document.getElementById('set-appearance-theme')?.value || 'system';
    APP_APPEARANCE.density = document.getElementById('set-appearance-density')?.value || 'comfortable';
    APP_APPEARANCE.width = document.getElementById('set-appearance-width')?.value || 'default';
    APP_APPEARANCE.textSize = document.getElementById('set-appearance-text-size')?.value || 'default';
    const saved = saveAppearancePrefs();
    if (!saved) {
        Toast.err('Appearance changed for this session, but browser storage is unavailable.');
        return;
    }
    Toast.ok('Appearance saved.');
}

async function saveReadingSettings() {
    try {
        const nextPrefs = {
            'reading:expand:media': document.getElementById('set-expand-media')?.value || 'default',
            'reading:expand:spoilers': document.getElementById('set-expand-spoilers')?.classList.contains('on') || false,
            'reading:autoplay:gifs': document.getElementById('set-autoplay-gifs')?.classList.contains('on') || false,
        };
        await Api.patch('/api/v1/accounts/update_credentials', {
            source: nextPrefs,
        });
        applyReadingPrefs(nextPrefs);
        Toast.ok('Reading settings saved.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function saveNotificationSettings() {
    try {
        await Api.put('/api/v1/notifications/policy', {
            for_not_following: document.getElementById('notif-not-following')?.value || 'accept',
            for_not_followers: document.getElementById('notif-not-followers')?.value || 'accept',
            for_new_accounts: document.getElementById('notif-new-accounts')?.value || 'accept',
            for_private_mentions: document.getElementById('notif-private-mentions')?.value || 'accept',
            for_limited_accounts: document.getElementById('notif-limited-accounts')?.value || 'accept',
        });
        Toast.ok('Notification settings saved.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function savePrivacySettings() {
    try {
        await Api.patch('/api/v1/accounts/update_credentials', {
            locked: document.getElementById('set-locked')?.classList.contains('on') || false,
            discoverable: document.getElementById('set-discoverable')?.classList.contains('on') || false,
            indexable: document.getElementById('set-indexable')?.classList.contains('on') || false,
        });
        Toast.ok('Privacy settings saved.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

function renderAccountRestrictionList(targetId, items, mode) {
    const root = document.getElementById(targetId);
    if (!root) return;
    if (!items.length) {
        root.innerHTML = `<div class="settings-empty">No ${mode === 'mute' ? 'muted' : 'blocked'} accounts.</div>`;
        return;
    }
    root.innerHTML = items.map(acct => `<div class="settings-chip-row">
        <div>
            <div class="settings-label" style="color:var(--text);font-weight:700">${esc(acct.display_name || acct.username)}</div>
            <div class="settings-label">@${esc(acct.acct || acct.username)}</div>
        </div>
        <button class="settings-chip-remove" type="button" onclick="${mode === 'mute' ? `removeMutedAccount('${escJsSq(acct.id)}')` : `removeBlockedAccount('${escJsSq(acct.id)}')`}">
            ${mode === 'mute' ? 'Unmute' : 'Unblock'}
        </button>
    </div>`).join('');
}

function renderDomainBlocks(domains) {
    const root = document.getElementById('settings-domain-blocks');
    if (!root) return;
    root.innerHTML = domains.length
        ? domains.map(domain => `<div class="settings-chip-row">
            <div class="settings-label" style="color:var(--text)">${esc(domain)}</div>
            <button class="settings-chip-remove" type="button" onclick="removeDomainBlock('${escJsSq(domain)}')">Remove</button>
        </div>`).join('')
        : '<div class="settings-empty">No blocked domains.</div>';
}

function renderFilters(filters) {
    const root = document.getElementById('settings-filters');
    if (!root) return;
    root.innerHTML = filters.length
        ? filters.map(filter => {
            const kws = (filter.keywords || []).map(k => k.keyword).join(', ');
            const contexts = (filter.context || []).join(', ');
            const ww = (filter.keywords || []).some(k => k.whole_word);
            return `<div class="settings-panel">
                <div class="settings-panel-head">
                    <div style="min-width:0;flex:1">
                        <div class="settings-panel-title">${esc(filter.title || kws || 'Filter')}</div>
                        <div class="settings-panel-meta">${esc(kws || 'No keywords')}</div>
                        <div class="settings-panel-meta">Action: ${esc(filter.filter_action || 'warn')} · Context: ${esc(contexts || 'home')}</div>
                        <div class="settings-pill-row">${ww ? '<span class="settings-pill">Whole-word matching</span>' : ''}</div>
                    </div>
                    <div style="display:flex;flex-direction:column;gap:.5rem;align-items:flex-end">
                        <button class="settings-chip-remove" type="button" onclick="loadFilterIntoForm('${escJsSq(filter.id)}')">Edit</button>
                        <button class="settings-chip-remove" type="button" onclick="removeFilter('${escJsSq(filter.id)}')">Delete</button>
                    </div>
                </div>
            </div>`;
        }).join('')
        : '<div class="settings-empty">No keyword filters.</div>';
}

function renderSessions(sessions) {
    const root = document.getElementById('settings-sessions');
    if (!root) return;
    const webSessions = sessions.filter(session => (session.app_name || '') === 'Web Client');
    const authorizedApps = sessions.filter(session => (session.app_name || '') !== 'Web Client');
    root.innerHTML = webSessions.length
        ? webSessions.map(session => `<div class="settings-panel">
            <div>
                <div class="settings-panel-title">${esc(session.app_name || 'Web Client')}${session.current ? ' · Current session' : ''}</div>
                <div class="settings-panel-meta">${esc(session.token_hint || '')}</div>
                <div class="settings-panel-meta">Created ${esc(timeAgo(session.created_at))}${session.last_used_at ? ' · Active ' + esc(timeAgo(session.last_used_at)) : ''}</div>
                <div class="settings-pill-row">${(session.scopes || []).map(scope => `<span class="settings-pill">${esc(scope)}</span>`).join('')}</div>
            </div>
            ${session.current
                ? `<button class="settings-chip-remove danger" type="button" onclick="revokeCurrentSession()">Sign out</button>`
                : `<button class="settings-chip-remove" type="button" onclick="revokeSession('${escJsSq(session.id)}')">Revoke</button>`}
        </div>`).join('')
        : '<div class="settings-empty">No active web sessions.</div>';
    const appRoot = document.getElementById('settings-authorized-apps');
    if (appRoot) {
        appRoot.innerHTML = authorizedApps.length
            ? authorizedApps.map(session => `<div class="settings-panel">
                <div class="settings-panel-head">
                    <div style="min-width:0;flex:1">
                        <div class="settings-panel-title">${esc(session.app_name || 'Authorized application')}</div>
                        <div class="settings-panel-meta">${esc(session.token_hint || '')}</div>
                        <div class="settings-panel-meta">Created ${esc(timeAgo(session.created_at))}${session.last_used_at ? ' · Active ' + esc(timeAgo(session.last_used_at)) : ''}</div>
                        ${session.app_website ? `<div class="settings-panel-meta">${esc(session.app_website)}</div>` : ''}
                        <div class="settings-pill-row">${(session.scopes || []).map(scope => `<span class="settings-pill">${esc(scope)}</span>`).join('')}</div>
                    </div>
                    <button class="settings-chip-remove" type="button" onclick="revokeSession('${escJsSq(session.id)}')">Revoke</button>
                </div>
            </div>`).join('')
            : '<div class="settings-empty">No authorized applications.</div>';
    }
}

function renderAliases(aliases) {
    const root = document.getElementById('settings-aliases');
    if (!root) return;
    root.innerHTML = aliases.length
        ? aliases.map(acct => `<div class="settings-chip-row">
            <div>
                <div class="settings-label" style="color:var(--text);font-weight:700">${esc(acct.display_name || acct.username)}</div>
                <div class="settings-label">@${esc(acct.acct || acct.username)}</div>
            </div>
            <button class="settings-chip-remove" type="button" onclick="removeMigrationAlias('${escJsSq(acct.acct || '')}')">Remove</button>
        </div>`).join('')
        : '<div class="settings-empty">No migration aliases.</div>';
}

function renderDeveloperApps(apps) {
    const root = document.getElementById('settings-developer-apps');
    if (!root) return;
    root.innerHTML = apps.length
        ? apps.map(app => `<div class="settings-chip-row" style="align-items:flex-start">
            <div style="min-width:0;flex:1">
                <div class="settings-label" style="color:var(--text);font-weight:700">${esc(app.name)}</div>
                <div class="settings-label">Scopes: ${esc((app.scopes || []).join(', ') || 'none')}</div>
                <div class="settings-label">Redirect URI: ${esc(app.redirect_uri || 'urn:ietf:wg:oauth:2.0:oob')}</div>
                <div class="settings-label" style="word-break:break-all">Client ID: ${esc(app.client_id || '')}</div>
                <div class="settings-label" style="word-break:break-all">Client Secret: ${esc(app.client_secret || '')}</div>
            </div>
            <div style="display:flex;flex-direction:column;gap:.5rem;align-items:flex-end">
                <button class="settings-chip-remove" type="button" onclick="copyDeveloperSecret('${escJsSq(app.client_id || '')}','Client ID copied.')">Copy ID</button>
                <button class="settings-chip-remove" type="button" onclick="copyDeveloperSecret('${escJsSq(app.client_secret || '')}','Client secret copied.')">Copy secret</button>
                <button class="settings-chip-remove" type="button" onclick="createPersonalAccessToken('${escJsSq(app.id)}')">Create token</button>
                <button class="settings-chip-remove danger" type="button" onclick="deleteDeveloperApp('${escJsSq(app.id)}')">Delete app</button>
            </div>
        </div>`).join('')
        : '<div class="settings-empty">No developer applications yet.</div>';
    const select = document.getElementById('dev-token-app');
    if (select) {
        const current = select.value;
        select.innerHTML = `<option value="">Choose an application</option>` + apps.map(app => `<option value="${esc(app.id)}">${esc(app.name)}</option>`).join('');
        if (apps.some(app => app.id === current)) select.value = current;
    }
}

function renderDeveloperTokens(tokens) {
    const root = document.getElementById('settings-developer-tokens');
    if (!root) return;
    root.innerHTML = tokens.length
        ? tokens.map(token => `<div class="settings-chip-row" style="align-items:flex-start">
            <div style="min-width:0;flex:1">
                <div class="settings-label" style="color:var(--text);font-weight:700">${esc(token.app_name || 'Application token')}</div>
                <div class="settings-label">${esc(token.token_hint || '')}</div>
                <div class="settings-label">Scopes: ${esc((token.scopes || []).join(', ') || 'none')}</div>
                <div class="settings-label">Created ${esc(timeAgo(token.created_at))}${token.last_used_at ? ' · Active ' + esc(timeAgo(token.last_used_at)) : ''}</div>
            </div>
            <button class="settings-chip-remove danger" type="button" onclick="revokeDeveloperToken('${escJsSq(token.id)}')">Revoke</button>
        </div>`).join('')
        : '<div class="settings-empty">No personal access tokens created here.</div>';
}

function settingsGroupForTitle(title) {
    const map = {
        'Profile': 'profile',
        'Appearance': 'appearance',
        'Posting defaults': 'posting',
        'Home and timeline tabs': 'posting',
        'Reading': 'reading',
        'Notifications': 'notifications',
        'Privacy and reach': 'privacy',
        'Filters and mutes': 'privacy',
        'Authorized applications and sessions': 'access',
        'Developer applications': 'access',
        'Import and export': 'migration',
        'Account migration': 'migration',
        'Account security': 'security',
        'Administration': 'admin',
    };
    return map[title] || 'profile';
}

function setupSettingsTabs() {
    const col = document.getElementById('col-content');
    if (!col) return;
    const sections = Array.from(col.querySelectorAll('.settings-section'));
    if (!sections.length) return;

    sections.forEach(section => {
        const title = section.querySelector('.settings-title')?.textContent?.trim() || '';
        section.dataset.settingsGroup = settingsGroupForTitle(title);
    });

    const groups = [
        {id: 'profile', label: 'Profile'},
        {id: 'appearance', label: 'Appearance'},
        {id: 'posting', label: 'Posting'},
        {id: 'reading', label: 'Reading'},
        {id: 'notifications', label: 'Notifications'},
        {id: 'privacy', label: 'Privacy'},
        {id: 'access', label: 'Access'},
        {id: 'migration', label: 'Migration'},
        {id: 'security', label: 'Security'},
        ...(WCFG.isAdmin ? [{id: 'admin', label: 'Admin'}] : []),
    ].filter(group => sections.some(section => section.dataset.settingsGroup === group.id));

    let nav = document.getElementById('settings-tabs');
    if (!nav) {
        nav = document.createElement('div');
        nav.id = 'settings-tabs';
        nav.className = 'explore-tabs';
        nav.style.position = 'sticky';
        nav.style.top = '2.9rem';
        nav.style.zIndex = '9';
        nav.style.background = 'var(--surface)';
        nav.style.borderBottom = '1px solid var(--border)';
        col.insertBefore(nav, sections[0]);
    }

    nav.innerHTML = groups.map(group => `
        <button type="button" class="explore-tab settings-tab-btn" data-settings-tab="${esc(group.id)}"
            onclick="activateSettingsTab('${escJsSq(group.id)}')">${esc(group.label)}</button>
    `).join('');

    const active = groups.some(group => group.id === window.__settingsTab) ? window.__settingsTab : groups[0]?.id;
    activateSettingsTab(active || 'profile');
}

function activateSettingsTab(groupId) {
    window.__settingsTab = groupId;
    document.querySelectorAll('#settings-tabs .settings-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.settingsTab === groupId);
    });
    document.querySelectorAll('#col-content .settings-section').forEach(section => {
        section.style.display = section.dataset.settingsGroup === groupId ? '' : 'none';
    });
    window.scrollTo({top: 0, behavior: 'auto'});
}

async function refreshDeveloperApps() {
    const payload = await Api.get('/api/v1/developer/apps');
    renderDeveloperApps(payload.apps || []);
    renderDeveloperTokens(payload.tokens || []);
}

function collectDeveloperScopes() {
    return Array.from(document.querySelectorAll('input[name="dev-app-scope"]:checked')).map(el => el.value);
}

function collectDeveloperTokenScopes() {
    return Array.from(document.querySelectorAll('input[name="dev-token-scope"]:checked')).map(el => el.value);
}

function resetFilterForm() {
    const title = document.getElementById('set-filter-title');
    const keyword = document.getElementById('set-filter-keyword');
    const action = document.getElementById('set-filter-action');
    const id = document.getElementById('set-filter-id');
    const wholeWord = document.getElementById('set-filter-whole-word');
    if (title) title.value = '';
    if (keyword) keyword.value = '';
    if (action) action.value = 'warn';
    if (id) id.value = '';
    if (wholeWord) wholeWord.classList.remove('on');
    document.querySelectorAll('input[name="set-filter-context"]').forEach(el => {
        el.checked = ['home', 'notifications'].includes(el.value);
    });
}

async function loadFilterIntoForm(id) {
    try {
        const filter = await Api.get('/api/v1/filters/' + encodeURIComponent(id));
        document.getElementById('set-filter-id').value = filter.id;
        document.getElementById('set-filter-title').value = filter.title || '';
        document.getElementById('set-filter-keyword').value = (filter.keywords || []).map(k => k.keyword).join(', ');
        document.getElementById('set-filter-action').value = filter.filter_action || 'warn';
        document.getElementById('set-filter-whole-word').classList.toggle('on', !!(filter.keywords || []).some(k => k.whole_word));
        const contexts = new Set(filter.context || []);
        document.querySelectorAll('input[name="set-filter-context"]').forEach(el => {
            el.checked = contexts.has(el.value);
        });
        document.getElementById('set-filter-title')?.scrollIntoView({behavior: 'smooth', block: 'center'});
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

function prefillDeveloperTokenForm(appId) {
    const select = document.getElementById('dev-token-app');
    if (select) select.value = appId;
    hideDeveloperTokenBox();
    document.getElementById('dev-token-app')?.scrollIntoView({behavior: 'smooth', block: 'center'});
}

function buildDeveloperStatusCurl(token) {
    const baseUrl = String(window.location.origin || '').replace(/\/+$/, '');
    const safeToken = String(token || '').replace(/'/g, `'\"'\"'`);
    return [
        `curl -X POST '${baseUrl}/api/v1/statuses' \\`,
        `  -H 'Authorization: Bearer ${safeToken}' \\`,
        `  --data-urlencode 'status=Hello from Starling via curl'`
    ].join('\n');
}

function showDeveloperTokenBox(token) {
    const root = document.getElementById('settings-dev-token-once');
    const value = document.getElementById('settings-dev-token-value');
    const curl = document.getElementById('settings-dev-curl-value');
    if (!root || !value || !curl) return;
    value.textContent = token || '';
    curl.textContent = buildDeveloperStatusCurl(token || '');
    root.style.display = '';
}

async function createDeveloperApp() {
    const name = (document.getElementById('dev-app-name')?.value || '').trim();
    const website = (document.getElementById('dev-app-website')?.value || '').trim();
    const redirectUri = (document.getElementById('dev-app-redirect')?.value || '').trim() || 'urn:ietf:wg:oauth:2.0:oob';
    const scopes = collectDeveloperScopes();
    if (!name) { Toast.err('Enter an application name first.'); return; }
    if (!scopes.length) { Toast.err('Select at least one scope.'); return; }
    try {
        const created = await Api.post('/api/v1/developer/apps', {
            client_name: name,
            website,
            redirect_uris: redirectUri,
            scopes: scopes.join(' '),
        });
        document.getElementById('dev-app-name').value = '';
        document.getElementById('dev-app-website').value = '';
        document.getElementById('dev-app-redirect').value = 'urn:ietf:wg:oauth:2.0:oob';
        await refreshDeveloperApps();
        if (created?.id) {
            const select = document.getElementById('dev-token-app');
            if (select) select.value = created.id;
        }
        hideDeveloperTokenBox();
        Toast.ok('Developer application created. Create a token below to use it with curl.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function deleteDeveloperApp(id) {
    if (!confirm('Delete this developer application and all of its tokens?')) return;
    try {
        await Api.del('/api/v1/developer/apps/' + encodeURIComponent(id), {});
        await refreshDeveloperApps();
        Toast.ok('Developer application deleted.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function createPersonalAccessToken(appId) {
    const selectedAppId = appId || (document.getElementById('dev-token-app')?.value || '');
    const scopes = collectDeveloperTokenScopes();
    if (!selectedAppId) { Toast.err('Choose an application first.'); return; }
    if (!scopes.length) { Toast.err('Select at least one token scope.'); return; }
    try {
        const created = await Api.post('/api/v1/developer/apps/' + encodeURIComponent(selectedAppId) + '/tokens', {scopes: scopes.join(' ')});
        showDeveloperTokenBox(created.access_token || '');
        await refreshDeveloperApps();
        Toast.ok('Personal access token created. Copy it now, or use the curl example below.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function revokeDeveloperToken(id) {
    try {
        await Api.del('/api/v1/developer/tokens/' + encodeURIComponent(id), {});
        await refreshDeveloperApps();
        Toast.ok('Personal access token revoked.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function copyDeveloperSecret(value, message) {
    try {
        await copyText(value);
        Toast.ok(message);
    } catch {
        Toast.err('Could not copy to clipboard.');
    }
}

async function copyTokenFromSettings() {
    const value = document.getElementById('settings-dev-token-value')?.textContent || '';
    if (!value) return;
    await copyDeveloperSecret(value, 'Token copied.');
}

async function copyDeveloperCurlExample() {
    const value = document.getElementById('settings-dev-curl-value')?.textContent || '';
    if (!value) return;
    await copyDeveloperSecret(value, 'curl example copied.');
}

function hideDeveloperTokenBox() {
    const root = document.getElementById('settings-dev-token-once');
    const value = document.getElementById('settings-dev-token-value');
    const curl = document.getElementById('settings-dev-curl-value');
    if (root) root.style.display = 'none';
    if (value) value.textContent = '';
    if (curl) curl.textContent = '';
}

async function addAccountRestriction(mode) {
    const input = document.getElementById('set-account-acct');
    const acct = (input?.value || '').trim();
    if (!acct) { Toast.err('Enter an account handle first.'); return; }
    try {
        const resolved = await Api.get('/api/v1/accounts/lookup', {acct});
        const endpoint = '/api/v1/accounts/' + encodeURIComponent(resolved.id) + (mode === 'mute' ? '/mute' : '/block');
        await Api.post(endpoint, {});
        input.value = '';
        if (mode === 'mute') {
            const items = await Api.get('/api/v1/mutes');
            renderAccountRestrictionList('settings-muted-list', items, 'mute');
            Toast.ok('Account muted.');
        } else {
            const items = await Api.get('/api/v1/blocks');
            renderAccountRestrictionList('settings-blocked-list', items, 'block');
            Toast.ok('Account blocked.');
        }
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function removeMutedAccount(id) {
    try {
        await Api.post('/api/v1/accounts/' + encodeURIComponent(id) + '/unmute', {});
        renderAccountRestrictionList('settings-muted-list', await Api.get('/api/v1/mutes'), 'mute');
        Toast.ok('Account unmuted.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function removeBlockedAccount(id) {
    try {
        await Api.post('/api/v1/accounts/' + encodeURIComponent(id) + '/unblock', {});
        renderAccountRestrictionList('settings-blocked-list', await Api.get('/api/v1/blocks'), 'block');
        Toast.ok('Account unblocked.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function addDomainBlock() {
    const input = document.getElementById('set-domain-block');
    const domain = (input?.value || '').trim().toLowerCase();
    if (!domain) { Toast.err('Enter a domain first.'); return; }
    try {
        await Api.post('/api/v1/domain_blocks', {domain});
        input.value = '';
        renderDomainBlocks(await Api.get('/api/v1/domain_blocks'));
        Toast.ok('Domain blocked.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function removeDomainBlock(domain) {
    try {
        await Api.del('/api/v1/domain_blocks', {domain});
        renderDomainBlocks(await Api.get('/api/v1/domain_blocks'));
        Toast.ok('Domain unblocked.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function saveKeywordFilter() {
    const rawKeywords = (document.getElementById('set-filter-keyword')?.value || '').trim();
    const title = (document.getElementById('set-filter-title')?.value || '').trim();
    const action = document.getElementById('set-filter-action')?.value || 'warn';
    const context = Array.from(document.querySelectorAll('input[name="set-filter-context"]:checked')).map(el => el.value);
    const filterId = document.getElementById('set-filter-id')?.value || '';
    const wholeWord = document.getElementById('set-filter-whole-word')?.classList.contains('on') || false;
    const keywords = rawKeywords.split(',').map(s => s.trim()).filter(Boolean);
    if (!keywords.length) { Toast.err('Enter at least one keyword first.'); return; }
    if (!context.length) { Toast.err('Select at least one context.'); return; }
    try {
        const body = {
            title: title || keywords[0],
            context,
            filter_action: action,
            keywords_attributes: keywords.map(keyword => ({keyword, whole_word: wholeWord})),
        };
        if (filterId) await Api.put('/api/v1/filters/' + encodeURIComponent(filterId), body);
        else await Api.post('/api/v1/filters', body);
        resetFilterForm();
        renderFilters(await Api.get('/api/v1/filters'));
        Toast.ok(filterId ? 'Filter updated.' : 'Filter created.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function removeFilter(id) {
    try {
        await Api.del('/api/v1/filters/' + encodeURIComponent(id), {});
        if ((document.getElementById('set-filter-id')?.value || '') === id) resetFilterForm();
        renderFilters(await Api.get('/api/v1/filters'));
        Toast.ok('Filter deleted.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function revokeSession(id) {
    try {
        await Api.del('/api/v1/sessions/' + encodeURIComponent(id), {});
        renderSessions(await Api.get('/api/v1/sessions'));
        Toast.ok('Session revoked.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function revokeOtherSessions() {
    try {
        await Api.del('/api/v1/sessions', {scope: 'others'});
        renderSessions(await Api.get('/api/v1/sessions'));
        Toast.ok('Other sessions signed out.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function revokeCurrentSession() {
    try {
        await Api.del('/api/v1/sessions', {scope: 'current'});
        window.location.href = '/web/login';
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function addMigrationAlias() {
    const input = document.getElementById('set-migration-alias');
    const acct = (input?.value || '').trim();
    if (!acct) { Toast.err('Enter a remote account alias first.'); return; }
    try {
        await Api.post('/api/v1/accounts/aliases', {acct});
        input.value = '';
        renderAliases(await Api.get('/api/v1/accounts/aliases'));
        Toast.ok('Migration alias added.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function removeMigrationAlias(acct) {
    try {
        await Api.del('/api/v1/accounts/aliases/' + encodeURIComponent(acct), {});
        renderAliases(await Api.get('/api/v1/accounts/aliases'));
        Toast.ok('Migration alias removed.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function moveToDifferentAccount() {
    const acct = (document.getElementById('set-move-acct')?.value || '').trim();
    const password = document.getElementById('set-move-password')?.value || '';
    if (!acct || !password) { Toast.err('Fill in the new account and your current password.'); return; }
    try {
        await Api.post('/api/v1/accounts/move', {acct, current_password: password});
        document.getElementById('set-move-password').value = '';
        Toast.ok('Account move initiated.');
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function importFollowingCsv() {
    const input = document.getElementById('set-following-import');
    const file = input?.files?.[0];
    if (!file) { Toast.err('Choose a CSV file first.'); return; }
    try {
        const text = await file.text();
        const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
        const seen = new Set();
        const accts = [];
        for (const line of lines) {
            if (/^(Account address|#|handle|acct)/i.test(line)) continue;
            const cells = parseCsvRow(line);
            const acctCell = cells.find(cell => cell.includes('@')) || cells[0] || '';
            const acct = acctCell.replace(/^@/, '').trim();
            if (!acct || !acct.includes('@')) continue;
            const normalized = acct.toLowerCase();
            if (seen.has(normalized)) continue;
            seen.add(normalized);
            accts.push(acct);
        }
        if (!accts.length) { Toast.err('No account addresses found in the CSV.'); return; }
        let ok = 0, failed = 0;
        for (const acct of accts) {
            try {
                const account = await Api.get('/api/v1/accounts/lookup', {acct});
                await Api.post('/api/v1/accounts/' + encodeURIComponent(account.id) + '/follow', {});
                ok++;
            } catch {
                failed++;
            }
        }
        if (input) input.value = '';
        Toast.ok(`Import finished. ${ok} followed, ${failed} skipped, ${accts.length} parsed.`);
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function exportFollowCsv(type) {
    try {
        const allowed = type === 'followers' ? 'followers' : 'following';
        const res = await fetch('/api/v1/follows/export?type=' + encodeURIComponent(allowed), {
            headers: {Authorization: 'Bearer ' + WCFG.token},
        });
        if (!res.ok) throw new Error(await res.text() || 'Export failed');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = allowed + '.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function deleteOwnAccount() {
    const password = document.getElementById('set-delete-password')?.value || '';
    if (!password) { Toast.err('Enter your current password first.'); return; }
    if (!confirm('Delete this account permanently? This cannot be undone.')) return;
    try {
        await Api.del('/api/v1/account', {current_password: password});
        window.location.href = '/web/login';
    } catch (e) { Toast.err('Error: ' + esc(e.message)); }
}

async function savePassword() {
    const cur = document.getElementById('set-pw-cur')?.value ?? '';
    const nw  = document.getElementById('set-pw-new')?.value ?? '';
    const cfm = document.getElementById('set-pw-cfm')?.value ?? '';
    if (!cur || !nw || !cfm) { Toast.err('Fill in all fields.'); return; }
    if (nw !== cfm) { Toast.err('Passwords do not match.'); return; }
    if (nw.length < 8) { Toast.err('The new password must be at least 8 characters.'); return; }
    try {
        await Api.patch('/api/v1/accounts/update_credentials', {current_password: cur, password: nw});
        document.getElementById('set-pw-cur').value = '';
        document.getElementById('set-pw-new').value = '';
        document.getElementById('set-pw-cfm').value = '';
        Toast.ok('Password changed successfully.');
    } catch (e) { Toast.err(e.message || 'Error changing password.'); }
}

async function showFavourites() {
    setColHeader('Favorites'); clearContent(); _currentRenderFn = renderStatus;
    addLoadMoreBtn();
    await loadFeed('/api/v1/favourites', renderStatus);
}

async function showBookmarks() {
    setColHeader('Bookmarks'); clearContent(); _currentRenderFn = renderStatus;
    addLoadMoreBtn();
    await loadFeed('/api/v1/bookmarks', renderStatus);
}

async function showFollowers(accountId) {
    setColHeader('Followers', true); clearContent(); _currentRenderFn = renderAccount;
    addLoadMoreBtn();
    await loadFeed('/api/v1/accounts/' + accountId + '/followers', renderAccount);
}

async function showFollowing(accountId) {
    setColHeader('Following', true); clearContent(); _currentRenderFn = renderAccount;
    addLoadMoreBtn();
    await loadFeed('/api/v1/accounts/' + accountId + '/following', renderAccount);
}

async function showRebloggedBy(statusId) {
    setColHeader('Reposts', true, `navigateReplace('THREAD','${esc(statusId)}')`);
    clearContent();
    _currentRenderFn = renderAccount;
    try {
        const items = await Api.get('/api/v1/statuses/' + statusId + '/reblogged_by');
        if (!items.length) {
            document.getElementById('col-content').innerHTML = '<div class="feed-end">No reposts.</div>';
            return;
        }
        items.forEach(item => insertBeforeLoadMore(renderAccount(item)));
    } catch (e) {
        document.getElementById('col-content').innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

async function showFavouritedBy(statusId) {
    setColHeader('Likes', true, `navigateReplace('THREAD','${esc(statusId)}')`);
    clearContent();
    _currentRenderFn = renderAccount;
    try {
        const items = await Api.get('/api/v1/statuses/' + statusId + '/favourited_by');
        if (!items.length) {
            document.getElementById('col-content').innerHTML = '<div class="feed-end">No likes.</div>';
            return;
        }
        items.forEach(item => insertBeforeLoadMore(renderAccount(item)));
    } catch (e) {
        document.getElementById('col-content').innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

// ── Explore ──────────────────────────────────────────────────────────────────
let _exploreTab = 'posts';

async function showExplore(tab) {
    // tab can be a tab name ('posts','news','hashtags','people') or null/undefined for trending
    // Detect if we were called with a tag name from SEARCH redirect (legacy)
    if (tab && !['posts','news','hashtags','people'].includes(tab)) tab = null;

    _exploreTab = tab || _exploreTab || 'posts';
    setColHeader('Explore'); clearContent();
    _currentRenderFn = null;

    const col = document.getElementById('col-content');

    // Search bar at the top (unified search + explore)
    col.insertAdjacentHTML('beforeend', `
        <div class="explore-search-bar">
            <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
            <input type="search" id="explore-search-input" placeholder="Search accounts, posts, hashtags..." autocomplete="off">
        </div>
        <div id="explore-search-results" style="display:none"></div>
        <div id="explore-trending-area">
    `);

    const tabs = `<div class="explore-tabs">
        <div class="explore-tab${_exploreTab==='posts'    ? ' active':''}" onclick="showExplore('posts')">Posts</div>
        <div class="explore-tab${_exploreTab==='news'     ? ' active':''}" onclick="showExplore('news')">News</div>
        <div class="explore-tab${_exploreTab==='hashtags' ? ' active':''}" onclick="showExplore('hashtags')">Hashtags</div>
        <div class="explore-tab${_exploreTab==='people'   ? ' active':''}" onclick="showExplore('people')">People</div>
    </div>`;
    document.getElementById('explore-trending-area').insertAdjacentHTML('beforeend', tabs);
    const trendingArea = document.getElementById('explore-trending-area');

    // Wire up search input
    const searchInput = document.getElementById('explore-search-input');
    if (_pendingExploreQuery) {
        searchInput.value = _pendingExploreQuery;
    }
    let _exploreSearchDebounce = null;
    searchInput.addEventListener('input', e => {
        clearTimeout(_exploreSearchDebounce);
        const q = e.target.value.trim();
        const sr = document.getElementById('explore-search-results');
        if (!q) {
            sr.style.display = 'none';
            trendingArea.style.display = '';
            return;
        }
        trendingArea.style.display = 'none';
        sr.style.display = '';
        sr.innerHTML = '<div class="feed-loading">Searching...</div>';
        _exploreSearchDebounce = setTimeout(() => doExploreSearch(q), 380);
    });
    searchInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') { clearTimeout(_exploreSearchDebounce); doExploreSearch(searchInput.value.trim()); }
    });
    syncRightSearchInput(searchInput.value.trim());

    if (_pendingExploreQuery) {
        const queued = _pendingExploreQuery;
        _pendingExploreQuery = '';
        trendingArea.style.display = 'none';
        document.getElementById('explore-search-results').style.display = '';
        await doExploreSearch(queued);
        return;
    }

    if (_exploreTab === 'posts') {
        _currentRenderFn = renderStatus;
        addLoadMoreBtn();
        await loadFeed('/api/v1/trends/statuses', renderStatus);

    } else if (_exploreTab === 'news') {
        const links = await Api.get('/api/v1/trends/links', {limit: 20}).catch(() => []);
        if (!links.length) { trendingArea.insertAdjacentHTML('beforeend', '<p style="padding:2rem;color:var(--text2);text-align:center">No trending links</p>'); return; }
        const html = links.map(l => {
            const uses = (l.history ?? []).reduce((s, h) => s + parseInt(h.uses ?? 0), 0);
            return `<div class="status-card">
                ${renderCard(l)}
                <div style="padding:0 1rem 1rem;color:var(--text2);font-size:.85rem">${uses} recent shares</div>
            </div>`;
        }).join('');
        trendingArea.insertAdjacentHTML('beforeend', html);

    } else if (_exploreTab === 'hashtags') {
        const tags = await Api.get('/api/v1/trends/tags', {limit: 20}).catch(() => []);
        if (!tags.length) { trendingArea.insertAdjacentHTML('beforeend', '<p style="padding:2rem;color:var(--text2);text-align:center">No trending hashtags</p>'); return; }
        const html = tags.map(t => {
            const uses = (t.history ?? []).reduce((s, h) => s + parseInt(h.uses ?? 0), 0);
            return `<div class="explore-tag-item" onclick="navigate('TAG_TIMELINE','${escJsSq(t.name)}')">
                <div>
                    <div class="explore-tag-name">#${esc(t.name)}</div>
                    <div class="explore-tag-count">${uses} posts in the last 7 days</div>
                </div>
                <svg viewBox="0 0 24 24" width="18" height="18" fill="var(--text3)"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>
            </div>`;
        }).join('');
        trendingArea.insertAdjacentHTML('beforeend', html);

    } else if (_exploreTab === 'people') {
        const people = await Api.get('/api/v1/trends/people', {limit: 20}).catch(() => []);
        if (!people.length) { trendingArea.insertAdjacentHTML('beforeend', '<p style="padding:2rem;color:var(--text2);text-align:center">No trending people</p>'); return; }
        const ids = people.map(a => a.id);
        const rels = await Api.get('/api/v1/accounts/relationships', {'id[]': ids}).catch(() => []);
        const relMap = {};
        rels.forEach(r => { if (r) relMap[r.id] = r; });

        const html = people.map(a => {
            const rel = relMap[a.id] || {};
            const following = !!rel.following;
            const requested = !!rel.requested && !following;
            const bio = a.note ? a.note.replace(/<[^>]+>/g, '').trim() : '';
            return `<div class="explore-people-item">
                <img class="explore-people-avatar" src="${esc(a.avatar)}" alt="" loading="lazy" onclick="navigate('PROFILE','${escJsSq(a.id)}')">
                <div class="explore-people-info" onclick="navigate('PROFILE','${escJsSq(a.id)}')">
                    <div class="explore-people-name">${esc(a.display_name || a.username)}</div>
                    <div class="explore-people-acct">@${esc(a.acct)}</div>
                    ${bio ? `<div class="explore-people-bio">${esc(bio)}</div>` : ''}
                </div>
                <button class="right-suggest-follow${following || requested ? ' following' : ''}"
                    data-account-id="${esc(a.id)}"
                    data-following="${following ? '1' : '0'}"
                    data-requested="${requested ? '1' : '0'}"
                    onclick="toggleRightFollow(this)">${following ? 'Following' : (requested ? 'Requested' : 'Follow')}</button>
            </div>`;
        }).join('');
        trendingArea.insertAdjacentHTML('beforeend', html);
    }
}

async function doExploreSearch(q) {
    const sr = document.getElementById('explore-search-results');
    if (!sr || !q) return;
    syncRightSearchInput(q);
    const reqId = ++_exploreSearchReqSeq;
    sr.innerHTML = '<div class="feed-loading">Searching...</div>';
    try {
        const r = await Api.get('/api/v2/search', {q, resolve: true, limit: 10});
        if (reqId !== _exploreSearchReqSeq) return;
        let html = '';
        if (r.accounts?.length)  { html += '<div class="search-section-title">Accounts</div>';   r.accounts.forEach(a  => html += renderAccount(a)); }
        if (r.statuses?.length)  { html += '<div class="search-section-title">Posts</div>';      r.statuses.forEach(s  => html += renderStatus(s)); }
        if (r.hashtags?.length)  { html += '<div class="search-section-title">Hashtags</div>';    r.hashtags.forEach(h  => html += `<div class="hashtag-item"><a href="#" onclick="navigate('TAG_TIMELINE','${escJsSq(h.name)}')">#${esc(h.name)}</a></div>`); }
        if (!html) html = '<div class="feed-end">No results.</div>';
        sr.innerHTML = html;
    } catch (e) {
        if (reqId !== _exploreSearchReqSeq) return;
        sr.innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

function renderListItem(list) {
    return `
    <div class="list-item" draggable="true" data-list-id="${esc(list.id)}">
        <span class="list-drag-handle" title="Drag to reorder">
            <svg viewBox="0 0 24 24"><path d="M11 18c0 1.1-.9 2-2 2s-2-.9-2-2 .9-2 2-2 2 .9 2 2zm-2-8c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0-6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm6 4c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
        </span>
        <svg class="list-item-icon" viewBox="0 0 24 24"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg>
        <span class="list-item-title" onclick="navigate('LIST_TIMELINE','${escJsSq(list.id)}')">${esc(list.title)}</span>
        <div class="list-actions">
            <button class="list-act-btn" title="Members" onclick="showListMembers('${escJsSq(list.id)}','${escJsSq(list.title)}')">
                <svg viewBox="0 0 24 24"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
            </button>
            <button class="list-act-btn" title="Edit name" onclick="editListTitle('${escJsSq(list.id)}','${escJsSq(list.title)}')">
                <svg viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
            </button>
            <button class="list-act-btn del" title="Delete list" onclick="deleteList('${escJsSq(list.id)}','${escJsSq(list.title)}')">
                <svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
            </button>
        </div>
    </div>`;
}

async function showLists() {
    setColHeader('Lists'); clearContent();
    const content = document.getElementById('col-content');
    content.innerHTML = '<div class="feed-loading">Loading...</div>';
    try {
        const lists = await Api.get('/api/v1/lists');
        content.innerHTML = `
        <div class="lists-toolbar">
            <h2>Your lists</h2>
            <button class="btn-new-list" onclick="createList()">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-2 10h-4v4h-2v-4H7v-2h4V7h2v4h4v2z"/></svg>
                New list
            </button>
        </div>
        ${lists.length ? lists.map(renderListItem).join('') : '<div class="feed-end">No lists. Create one with the button above.</div>'}`;
        if (lists.length > 1) _initListDrag(content);
    } catch (e) {
        content.innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

function _initListDrag(container) {
    let dragSrc = null;

    container.addEventListener('dragstart', e => {
        const item = e.target.closest('.list-item');
        if (!item) return;
        dragSrc = item;
        item.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', item.dataset.listId);
    });

    container.addEventListener('dragend', e => {
        const item = e.target.closest('.list-item');
        if (item) item.classList.remove('dragging');
        container.querySelectorAll('.list-item.drag-over').forEach(el => el.classList.remove('drag-over'));
        dragSrc = null;
    });

    container.addEventListener('dragover', e => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        const item = e.target.closest('.list-item');
        container.querySelectorAll('.list-item.drag-over').forEach(el => el.classList.remove('drag-over'));
        if (item && item !== dragSrc) item.classList.add('drag-over');
    });

    container.addEventListener('dragleave', e => {
        const item = e.target.closest('.list-item');
        if (item) item.classList.remove('drag-over');
    });

    container.addEventListener('drop', async e => {
        e.preventDefault();
        const target = e.target.closest('.list-item');
        if (!target || !dragSrc || target === dragSrc) return;
        target.classList.remove('drag-over');

        // Reorder DOM: insert dragSrc before target
        const rect = target.getBoundingClientRect();
        const after = e.clientY > rect.top + rect.height / 2;
        if (after) target.after(dragSrc);
        else target.before(dragSrc);

        // Collect new order and persist
        const ids = [...container.querySelectorAll('.list-item')].map(el => el.dataset.listId);
        try {
            await Api.post('/api/v1/lists/reorder', {order: ids});
            _homeLists = null; // invalidate tabs
            _renderHomeTabBar();
        } catch (err) { Toast.err('Error saving order: ' + err.message); }
    });
}

async function createList() {
    const title = prompt('Name for the new list:');
    if (!title?.trim()) return;
    try {
        await Api.post('/api/v1/lists', {title: title.trim()});
        _homeLists = null; // invalidate tabs cache
        showLists();
    } catch (e) { Toast.err('Error: ' + e.message); }
}

async function editListTitle(id, currentTitle) {
    const title = prompt('New name:', currentTitle);
    if (!title?.trim() || title.trim() === currentTitle) return;
    try {
        await Api.put('/api/v1/lists/' + id, {title: title.trim()});
        _homeLists = null; // invalidate tabs cache
        const el = document.querySelector(`.list-item[data-list-id="${id}"] .list-item-title`);
        if (el) el.textContent = title.trim();
    } catch (e) { Toast.err('Error: ' + e.message); }
}

async function deleteList(id, title) {
    if (!confirm('Delete the list "' + title + '"?')) return;
    try {
        await Api.del('/api/v1/lists/' + id);
        _homeLists = null; // invalidate tabs cache
        // if deleted list was active tab, reset to home
        if (_homeTab === id) _homeTab = 'home';
        document.querySelector(`.list-item[data-list-id="${id}"]`)?.remove();
    } catch (e) { Toast.err('Error: ' + e.message); }
}

async function showListMembers(listId, listTitle) {
    setColHeader('Members'); clearContent();
    const content = document.getElementById('col-content');
    content.innerHTML = '<div class="feed-loading">Loading...</div>';
    try {
        const members = await Api.get('/api/v1/lists/' + listId + '/accounts', {limit: 80});
        content.innerHTML = `
        <div class="members-header">
            <button class="members-back" onclick="navigate('LISTS')" title="Back">
                <svg viewBox="0 0 24 24"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg>
            </button>
            <span class="members-title">${esc(listTitle)}</span>
        </div>
        <div class="members-search">
            <input type="search" id="member-search-input" placeholder="Search for an account to add..." autocomplete="off">
            <button onclick="searchToAddMember('${escJsSq(listId)}')">Search</button>
        </div>
        <div id="member-search-results"></div>
        <div id="member-list">
            ${members.length
                ? members.map(a => renderMemberRow(a, listId, true)).join('')
                : '<div class="feed-end">No members. Search for an account above to add one.</div>'}
        </div>`;
        document.getElementById('member-search-input').addEventListener('keydown', e => {
            if (e.key === 'Enter') searchToAddMember(listId);
        });
    } catch (e) {
        content.innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

function renderMemberRow(account, listId, isMember) {
    const btn = isMember
        ? `<button class="member-remove" onclick="removeListMember('${escJsSq(listId)}','${escJsSq(account.id)}',this)">Remove</button>`
        : `<button class="member-add" onclick="addListMember('${escJsSq(listId)}','${escJsSq(account.id)}',this)">Add</button>`;
    return `
    <div class="member-row" data-account-id="${esc(account.id)}">
        <img src="${esc(account.avatar)}" alt="" onclick="navigate('PROFILE','${escJsSq(account.id)}')">
        <div class="member-info">
            <div class="member-name" onclick="navigate('PROFILE','${escJsSq(account.id)}')">${esc(account.display_name || account.username)}</div>
            <div class="member-acct">@${esc(account.acct)}</div>
        </div>
        ${btn}
    </div>`;
}

async function searchToAddMember(listId) {
    const q = document.getElementById('member-search-input')?.value?.trim();
    if (!q) return;
    const res = document.getElementById('member-search-results');
    if (!res) return;
    const reqId = ++_memberSearchReqSeq;
    res.innerHTML = '<div class="feed-loading">Searching...</div>';
    try {
        const r = await Api.get('/api/v2/search', {q, resolve: true, limit: 5, type: 'accounts'});
        if (reqId !== _memberSearchReqSeq) return;
        if (!r.accounts?.length) { res.innerHTML = '<div class="feed-end" style="padding:.75rem 1.25rem">No results.</div>'; return; }
        res.innerHTML = r.accounts.map(a => renderMemberRow(a, listId, false)).join('');
    } catch (e) {
        if (reqId !== _memberSearchReqSeq) return;
        res.innerHTML = '<div class="feed-error" style="padding:.75rem 1.25rem">Error: ' + esc(e.message) + '</div>';
    }
}

async function addListMember(listId, accountId, btn) {
    btn.disabled = true;
    try {
        await Api.post('/api/v1/lists/' + listId + '/accounts', {account_ids: [accountId]});
        btn.textContent = 'Added ✓';
        btn.className = 'member-remove';
        btn.onclick = function() { removeListMember(listId, accountId, btn); };
    } catch (e) { Toast.err('Error: ' + e.message); btn.disabled = false; }
}

async function removeListMember(listId, accountId, btn) {
    btn.disabled = true;
    try {
        await Api.del('/api/v1/lists/' + listId + '/accounts', {account_ids: [accountId]});
        btn.closest('.member-row')?.remove();
    } catch (e) { Toast.err('Error: ' + e.message); btn.disabled = false; }
}

async function showTagTimeline(tag) {
    setColHeader('#' + tag, true); clearContent(); _currentRenderFn = renderStatus;
    addLoadMoreBtn();
    await loadFeed('/api/v1/timelines/tag/' + encodeURIComponent(tag), renderStatus);
}

async function showListTimeline(id) {
    clearContent(); _currentRenderFn = renderStatus;
    setColHeader('List');
    try {
        const list = await Api.get('/api/v1/lists/' + id);
        setColHeader(list.title);
    } catch {}
    addLoadMoreBtn();
    await loadFeed('/api/v1/timelines/list/' + id, renderStatus);
}

async function showEditProfile() {
    setColHeader('Edit Profile'); clearContent();
    const content = document.getElementById('col-content');
    content.innerHTML = '<div class="feed-loading">Loading...</div>';
    try {
        const account = await Api.get('/api/v1/accounts/verify_credentials');
        const sourceFields = Array.isArray(account.source?.fields) ? account.source.fields : [];
        const fields = Array.from({length: 4}, (_, i) => ({
            name: sourceFields[i]?.name || '',
            value: sourceFields[i]?.value || '',
            verified_at: sourceFields[i]?.verified_at || null,
        }));
        const fullAcct = '@' + (account.username || WCFG.myUsername) + '@' + WCFG.domain;
        const bannerHtml = account.header && !account.header.includes('missing')
            ? `<img src="${esc(account.header)}" alt="">`
            : `<div class="ep-banner-placeholder">Click to add a banner</div>`;
        const bioText = account.source?.note ?? htmlToPlainText(account.note || '');
        content.innerHTML = `
        <div class="edit-profile-form">
            <div class="ep-hero">
                <img id="ep-hero-avatar" src="${esc(account.avatar)}" alt="">
                <div class="ep-hero-meta">
                    <div class="ep-hero-name">${esc(account.display_name || account.username)}</div>
                    <div class="ep-hero-handle">${esc(fullAcct)}</div>
                    <div class="ep-chip-row">
                        ${account.bot ? '<span class="ep-chip">Bot account</span>' : ''}
                        ${account.locked ? '<span class="ep-chip">Follow approval required</span>' : ''}
                        ${account.discoverable ? '<span class="ep-chip">Discoverable</span>' : ''}
                        ${account.noindex ? '' : '<span class="ep-chip">Indexable</span>'}
                    </div>
                </div>
            </div>
            <div class="ep-section">
                <div class="ep-section-title">Images</div>
                <div class="ep-field"><label>Banner</label>
                    <label class="ep-banner" style="cursor:pointer">
                        ${bannerHtml}
                        <div class="ep-banner-overlay"><span>Change banner</span></div>
                        <input type="file" id="ep-header-input" accept="image/*" style="display:none">
                    </label>
                    <div class="ep-help">Use a wide image for the profile header.</div>
                </div>
                <div class="ep-avatar-row">
                    <label class="ep-avatar-wrap" style="cursor:pointer">
                        <img id="ep-avatar-img" src="${esc(account.avatar)}" alt="">
                        <div class="ep-avatar-overlay"><svg viewBox="0 0 24 24"><path d="M12 15.2A3.2 3.2 0 0 1 8.8 12 3.2 3.2 0 0 1 12 8.8 3.2 3.2 0 0 1 15.2 12 3.2 3.2 0 0 1 12 15.2M12 7a5 5 0 0 0-5 5 5 5 0 0 0 5 5 5 5 0 0 0 5-5 5 5 0 0 0-5-5m0-5.5c-.3 0-.5.2-.5.5v2c0 .3.2.5.5.5s.5-.2.5-.5V2c0-.3-.2-.5-.5-.5z"/></svg></div>
                        <input type="file" id="ep-avatar-input" accept="image/*" style="display:none">
                    </label>
                    <div class="ep-help">Click the avatar to upload a new square profile image.</div>
                </div>
            </div>
            <div class="ep-section">
                <div class="ep-section-title">Basics</div>
                <div class="ep-field-grid">
                    <div class="ep-field">
                        <label>Display name</label>
                        <input type="text" id="ep-display-name" value="${esc(account.display_name || '')}" maxlength="100" placeholder="Your name">
                        <div class="ep-inline-meta">
                            <div class="ep-help">Shown across the public site and the web client.</div>
                            <div class="ep-counter" id="ep-display-name-counter">0/100</div>
                        </div>
                    </div>
                    <div class="ep-field">
                        <label>Account handle</label>
                        <div class="ep-readonly">${esc(fullAcct)}</div>
                        <div class="ep-help">Handles are identity URLs here, so they are read-only.</div>
                    </div>
                </div>
                <div class="ep-field">
                    <label>Bio</label>
                    <textarea id="ep-note" rows="5" maxlength="500" placeholder="Say a little about yourself...">${esc(bioText)}</textarea>
                    <div class="ep-inline-meta">
                        <div class="ep-help">Plain text is fine. Links can go in the profile metadata below.</div>
                        <div class="ep-counter" id="ep-note-counter">0/500</div>
                    </div>
                </div>
            </div>
            <div class="ep-section">
                <div class="ep-section-title">Profile metadata</div>
                <div class="ep-help" style="margin-bottom:.9rem">Add up to four links or labels. Public URLs can verify themselves with rel="me".</div>
                <div class="ep-fields">
                    ${fields.map((field, i) => `
                    <div class="ep-field-row">
                        <div class="ep-field-row-head">
                            <div class="ep-help">Field ${i + 1}</div>
                            ${field.verified_at ? `<span class="ep-field-badge" title="${esc(formatDate(field.verified_at))}">Verified</span>` : ''}
                        </div>
                        <div class="ep-field-grid">
                            <div class="ep-field">
                                <label>Label</label>
                                <input type="text" id="ep-field-name-${i}" value="${esc(field.name)}" maxlength="80" placeholder="Website">
                            </div>
                            <div class="ep-field">
                                <label>Value or URL</label>
                                <input type="text" id="ep-field-value-${i}" value="${esc(field.value)}" maxlength="255" placeholder="https://example.org">
                            </div>
                        </div>
                        <button class="ep-field-remove" type="button" onclick="EditProfile.clearField(${i})">Clear field</button>
                    </div>`).join('')}
                </div>
            </div>
            <div class="ep-section">
                <div class="ep-section-title">Privacy and identity</div>
                <div class="ep-toggle-grid">
                    <div class="ep-toggle-row" onclick="document.getElementById('ep-bot')?.classList.toggle('on')">
                        <div class="ep-toggle-copy">
                            <strong>Bot account</strong>
                            <span>Label this profile as automated.</span>
                        </div>
                        <button id="ep-bot" class="toggle-btn${account.bot ? ' on' : ''}" type="button" onclick="event.stopPropagation();this.classList.toggle('on')"><span class="toggle-knob"></span></button>
                    </div>
                    <div class="ep-toggle-row" onclick="document.getElementById('ep-locked')?.classList.toggle('on')">
                        <div class="ep-toggle-copy">
                            <strong>Require follow approval</strong>
                            <span>New followers need manual approval.</span>
                        </div>
                        <button id="ep-locked" class="toggle-btn${account.locked ? ' on' : ''}" type="button" onclick="event.stopPropagation();this.classList.toggle('on')"><span class="toggle-knob"></span></button>
                    </div>
                    <div class="ep-toggle-row" onclick="document.getElementById('ep-discoverable')?.classList.toggle('on')">
                        <div class="ep-toggle-copy">
                            <strong>Show in suggestions</strong>
                            <span>Allow discovery in profile and follow suggestions.</span>
                        </div>
                        <button id="ep-discoverable" class="toggle-btn${account.discoverable ? ' on' : ''}" type="button" onclick="event.stopPropagation();this.classList.toggle('on')"><span class="toggle-knob"></span></button>
                    </div>
                    <div class="ep-toggle-row" onclick="document.getElementById('ep-indexable')?.classList.toggle('on')">
                        <div class="ep-toggle-copy">
                            <strong>Allow search engine indexing</strong>
                            <span>Let public pages be indexed outside the fediverse.</span>
                        </div>
                        <button id="ep-indexable" class="toggle-btn${account.noindex ? '' : ' on'}" type="button" onclick="event.stopPropagation();this.classList.toggle('on')"><span class="toggle-knob"></span></button>
                    </div>
                </div>
            </div>
            <div class="ep-actions">
                <button class="ep-save-btn" id="ep-submit" onclick="EditProfile.submit()">Save changes</button>
                <span class="ep-status" id="ep-status"></span>
            </div>
        </div>`;
        document.getElementById('ep-display-name')?.addEventListener('input', () => EditProfile.updateCounter('ep-display-name', 'ep-display-name-counter', 100));
        document.getElementById('ep-note')?.addEventListener('input', () => EditProfile.updateCounter('ep-note', 'ep-note-counter', 500));
        EditProfile.updateCounter('ep-display-name', 'ep-display-name-counter', 100);
        EditProfile.updateCounter('ep-note', 'ep-note-counter', 500);
        document.getElementById('ep-avatar-input').addEventListener('change', function() { EditProfile.previewAvatar(this); });
        document.getElementById('ep-header-input').addEventListener('change', function() { EditProfile.previewHeader(this); });
    } catch (e) {
        content.innerHTML = '<div class="feed-error">Error: ' + esc(e.message) + '</div>';
    }
}

const EditProfile = {
    _avatarFile: null,
    _headerFile: null,

    updateCounter(inputId, counterId, limit) {
        const input = document.getElementById(inputId);
        const counter = document.getElementById(counterId);
        if (!input || !counter) return;
        const size = (input.value || '').length;
        counter.textContent = size + '/' + limit;
        counter.style.color = size > limit * 0.9 ? 'var(--red)' : 'var(--text2)';
    },

    collectFields() {
        return Array.from({length: 4}, (_, i) => ({
            name: (document.getElementById('ep-field-name-' + i)?.value || '').trim(),
            value: (document.getElementById('ep-field-value-' + i)?.value || '').trim(),
        })).filter(field => field.name || field.value);
    },

    clearField(index) {
        const name = document.getElementById('ep-field-name-' + index);
        const value = document.getElementById('ep-field-value-' + index);
        if (name) name.value = '';
        if (value) value.value = '';
    },

    previewAvatar(input) {
        const file = input.files[0];
        if (!file) return;
        this._avatarFile = file;
        document.getElementById('ep-avatar-img').src = URL.createObjectURL(file);
        const hero = document.getElementById('ep-hero-avatar');
        if (hero) hero.src = document.getElementById('ep-avatar-img').src;
    },

    previewHeader(input) {
        const file = input.files[0];
        if (!file) return;
        this._headerFile = file;
        const preview = input.closest('.ep-banner');
        const img = preview.querySelector('img') || document.createElement('img');
        img.src = URL.createObjectURL(file);
        if (!preview.querySelector('img')) { preview.querySelector('.ep-banner-placeholder')?.remove(); preview.prepend(img); }
    },

    async submit() {
        const btn    = document.getElementById('ep-submit');
        const status = document.getElementById('ep-status');
        btn.disabled = true;
        status.className = 'ep-status';
        status.textContent = 'Saving...';
        try {
            const fd = new FormData();
            fd.append('display_name', document.getElementById('ep-display-name').value);
            fd.append('note',         document.getElementById('ep-note').value);
            fd.append('bot', document.getElementById('ep-bot')?.classList.contains('on') ? '1' : '0');
            fd.append('locked', document.getElementById('ep-locked')?.classList.contains('on') ? '1' : '0');
            fd.append('discoverable', document.getElementById('ep-discoverable')?.classList.contains('on') ? '1' : '0');
            fd.append('indexable', document.getElementById('ep-indexable')?.classList.contains('on') ? '1' : '0');
            this.collectFields().forEach((field, i) => {
                fd.append(`fields_attributes[${i}][name]`, field.name);
                fd.append(`fields_attributes[${i}][value]`, field.value);
            });
            if (this._avatarFile) fd.append('avatar', this._avatarFile);
            if (this._headerFile) fd.append('header', this._headerFile);
            const account = await Api.patch('/api/v1/accounts/update_credentials', fd);
            status.className = 'ep-status ok';
            status.textContent = '✓ Saved!';
            this._avatarFile = null; this._headerFile = null;
            // Update nav
            const navAv = document.getElementById('nav-avatar');
            if (navAv && account.avatar) navAv.src = account.avatar;
            const nn = document.getElementById('nav-name');
            if (nn) nn.textContent = account.display_name || account.username;
            WCFG.myDisplayName = account.display_name || account.username;
            const heroName = document.querySelector('.ep-hero-name');
            if (heroName) heroName.textContent = account.display_name || account.username;
        } catch (e) {
            status.className = 'ep-status err';
            status.textContent = 'Error: ' + e.message;
        }
        btn.disabled = false;
    },
};

// ── Bottom Sheet ───────────────────────────────────────────────────────────
const BottomSheet = {
    open() {
        document.getElementById('bs-overlay').classList.add('open');
        document.getElementById('bottom-sheet').classList.add('open');
        document.body.style.overflow = 'hidden';
    },
    close() {
        document.getElementById('bs-overlay').classList.remove('open');
        document.getElementById('bottom-sheet').classList.remove('open');
        document.body.style.overflow = '';
    },
    toggle() {
        document.getElementById('bottom-sheet').classList.contains('open') ? this.close() : this.open();
    },
};

// ── Streaming (SSE) ────────────────────────────────────────────────────────
let _sse = null, _pendingPosts = 0, _pendingNotifs = 0, _sseDelay = 2000;

function startStreaming() {
    if (_sse) return;
    try {
        const url = '/api/v1/streaming/user';
        _sse = new EventSource(url);
        _sse.addEventListener('open', () => { _sseDelay = 2000; });
        _sse.addEventListener('update', e => {
            try {
                const s = JSON.parse(e.data);
                if (document.querySelector(`.status-card[data-id="${s.id}"]`)) return;
                _pendingPosts++;
                updateNewPostsBtn();
            } catch {}
        });
        _sse.addEventListener('notification', e => {
            try {
                const notif = JSON.parse(e.data || '{}');
                const notifId = String(notif?.id || e.lastEventId || '0');
                const seenFloor = notifIdGt(_notifSeenMaxId, _notifLastReadId) ? _notifSeenMaxId : _notifLastReadId;

                if (notifId && notifId !== '0') {
                    if (notifIdGte(seenFloor, notifId)) return;
                    if (notifIdGt(notifId, _notifSeenMaxId)) _notifSeenMaxId = notifId;
                    if (WCFG.view === 'NOTIFICATIONS') {
                        markNotificationsReadUpTo(notifId);
                        return;
                    }
                }
            } catch {}
            _pendingNotifs++;
            updateNotifBadge();
        });
        _sse.onerror = () => {
            _sse?.close();
            _sse = null;
            setTimeout(startStreaming, _sseDelay);
            _sseDelay = Math.min(_sseDelay * 2, 30000);
        };
    } catch {}
}

function updateNotifBadge() {
    const label = _pendingNotifs > 99 ? '99+' : String(_pendingNotifs);
    // Update both desktop sidebar and mobile bottom nav
    document.querySelectorAll('[data-view="NOTIFICATIONS"]').forEach(el => {
        let badge = el.querySelector('.notif-badge');
        if (!badge) {
            badge = document.createElement('span');
            badge.className = 'notif-badge';
            el.appendChild(badge);
        }
        badge.style.display = _pendingNotifs > 0 ? '' : 'none';
        badge.textContent   = label;
    });
}

async function checkUnreadNotifications() {
    try {
        const [markers, notifs] = await Promise.all([
            Api.get('/api/v1/markers', {'timeline[]': 'notifications'}).catch(() => ({})),
            Api.get('/api/v1/notifications', {limit: 1}).catch(() => []),
        ]);
        const lastRead  = String(markers?.notifications?.last_read_id ?? '0');
        const unreadCount = Number(markers?.notifications?.unread_count ?? NaN);
        _notifLastReadId = lastRead;
        if (!notifs.length) {
            _pendingNotifs = 0;
            updateNotifBadge();
            return;
        }
        const latestId  = notifs[0].id;
        if (notifIdGt(latestId, _notifSeenMaxId)) _notifSeenMaxId = latestId;
        if (WCFG.view === 'NOTIFICATIONS') {
            _pendingNotifs = 0;
            updateNotifBadge();
            return;
        }
        if (Number.isFinite(unreadCount) && unreadCount >= 0) {
            _pendingNotifs = unreadCount;
            updateNotifBadge();
            return;
        }
        if (lastRead === '0' || notifIdGt(latestId, lastRead)) {
            _pendingNotifs = 1;
            updateNotifBadge();
            return;
        }
        _pendingNotifs = 0;
        updateNotifBadge();
    } catch {}
}

function updateNewPostsBtn() {
    document.querySelectorAll('[data-view="HOME"] .notif-badge').forEach(el => el.remove());
    // Floating pill (only when on HOME view)
    const pill = document.getElementById('new-posts-pill');
    if (pill) {
        if (_pendingPosts > 0 && WCFG.view === 'HOME') {
            pill.textContent = _pendingPosts === 1
                ? '1 new post'
                : _pendingPosts + ' new posts';
            pill.style.display = '';
        } else {
            pill.style.display = 'none';
        }
    }
}

function loadNewPosts() {
    _pendingPosts = 0;
    updateNewPostsBtn();
    window.scrollTo({top: 0, behavior: 'smooth'});
    showHome(_homeTab);
}

// ── Navigation ─────────────────────────────────────────────────────────────
function navigate(view, id = null) {
    _cacheCurrentView(); // save scroll + content before leaving
    BottomSheet.close();
    // SEARCH is merged into EXPLORE
    if (view === 'SEARCH') view = 'EXPLORE';
    // Default PROFILE to own profile
    if (view === 'PROFILE' && !id) id = WCFG.myId;
    WCFG.view   = view;
    WCFG.viewId = id;
    // Hide/show floating pill. Keep pending Home updates visible until the
    // user explicitly reloads them or Home is refreshed.
    const pill = document.getElementById('new-posts-pill');
    if (view === 'HOME') { updateNewPostsBtn(); }
    else if (pill) pill.style.display = 'none';
    let url = '/web';
    if (view === 'LOCAL')              url = '/web/local';
    else if (view === 'NOTIFICATIONS') url = '/web/notifications';
    else if (view === 'EXPLORE')       url = '/web/explore';
    else if (view === 'FAVOURITES')    url = '/web/favourites';
    else if (view === 'BOOKMARKS')     url = '/web/bookmarks';
    else if (view === 'LISTS')         url = '/web/lists';
    else if (view === 'LIST_TIMELINE') url = '/web/list/' + id;
    else if (view === 'THREAD')        url = '/web/thread/' + id;
    else if (view === 'PROFILE')       url = '/web/profile/' + id;
    else if (view === 'FOLLOWERS')     url = '/web/profile/' + id + '/followers';
    else if (view === 'FOLLOWING')     url = '/web/profile/' + id + '/following';
    else if (view === 'TAG_TIMELINE')  url = '/web/tag/' + encodeURIComponent(id);
    else if (view === 'CONVERSATIONS') url = '/web/conversations';
    else if (view === 'SETTINGS')      url = '/web/settings';
    else if (view === 'EDIT_PROFILE')  url = '/web/edit-profile';
    // Store _homeTab in state so back navigation restores the correct tab
    history.pushState({view, id, homeTab: _homeTab}, '', url);
    setActiveNav(view);
    dispatchView(view, id);
}

function navigateReplace(view, id = null) {
    _cacheCurrentView();
    BottomSheet.close();
    if (view === 'SEARCH') view = 'EXPLORE';
    if (view === 'PROFILE' && !id) id = WCFG.myId;
    WCFG.view   = view;
    WCFG.viewId = id;
    const pill = document.getElementById('new-posts-pill');
    if (view === 'HOME') { updateNewPostsBtn(); }
    else if (pill) pill.style.display = 'none';
    let url = '/web';
    if (view === 'LOCAL')              url = '/web/local';
    else if (view === 'NOTIFICATIONS') url = '/web/notifications';
    else if (view === 'EXPLORE')       url = '/web/explore';
    else if (view === 'FAVOURITES')    url = '/web/favourites';
    else if (view === 'BOOKMARKS')     url = '/web/bookmarks';
    else if (view === 'LISTS')         url = '/web/lists';
    else if (view === 'LIST_TIMELINE') url = '/web/list/' + id;
    else if (view === 'THREAD')        url = '/web/thread/' + id;
    else if (view === 'PROFILE')       url = '/web/profile/' + id;
    else if (view === 'FOLLOWERS')     url = '/web/profile/' + id + '/followers';
    else if (view === 'FOLLOWING')     url = '/web/profile/' + id + '/following';
    else if (view === 'TAG_TIMELINE')  url = '/web/tag/' + encodeURIComponent(id);
    else if (view === 'CONVERSATIONS') url = '/web/conversations';
    else if (view === 'SETTINGS')      url = '/web/settings';
    else if (view === 'EDIT_PROFILE')  url = '/web/edit-profile';
    history.replaceState({view, id, homeTab: _homeTab}, '', url);
    setActiveNav(view);
    dispatchView(view, id);
}

// (popstate is handled in the DOMContentLoaded block below, after the cache helpers are ready)

function dispatchView(view, id) {
    switch (view) {
        case 'HOME':           showHome();             break;
        case 'LOCAL':          showLocal();            break;
        case 'NOTIFICATIONS':  showNotifications('all'); break;
        case 'THREAD':         showThread(id);         break;
        case 'PROFILE':        showProfile(id);        break;
        case 'SEARCH':         showExplore();          break;
        case 'FAVOURITES':     showFavourites();       break;
        case 'BOOKMARKS':      showBookmarks();        break;
        case 'LISTS':          showLists();            break;
        case 'LIST_TIMELINE':  showListTimeline(id);   break;
        case 'TAG_TIMELINE':   showTagTimeline(id);    break;
        case 'EXPLORE':        showExplore(id);        break;
        case 'CONVERSATIONS':  showConversations();    break;
        case 'FOLLOWERS':      showFollowers(id);      break;
        case 'FOLLOWING':      showFollowing(id);      break;
        case 'SETTINGS':       showSettings();         break;
        case 'EDIT_PROFILE':   showEditProfile();      break;
    }
}

function setActiveNav(view) {
    document.querySelectorAll('.nav-link[data-view], .bn-item[data-view], .bs-item[data-view]').forEach(a => {
        a.classList.toggle('active', a.dataset.view === view);
    });
}

// ── Actions ────────────────────────────────────────────────────────────────
function showRepostMenu(e, id, btn) {
    e.stopPropagation();
    // If already boosted, just unboosted directly
    if (btn.classList.contains('active')) { toggleBoost(id, btn); return; }
    // Close any existing dropdown
    document.querySelectorAll('.repost-dropdown,.post-menu-dropdown').forEach(d => d.remove());
    const dd = document.createElement('div');
    dd.className = 'repost-dropdown';
    const boostBtn = btn; // capture reference before dropdown is removed
    dd.innerHTML = `
        <button class="repost-option" data-action="boost">
            <svg viewBox="0 0 24 24"><path d="M17 1L21 5L17 9V6H7V12H5V6C5 4.9 5.9 4 7 4H17V1ZM7 23L3 19L7 15V18H17V12H19V18C19 19.1 18.1 20 17 20H7V23Z"/></svg>
            Repost
        </button>
        <button class="repost-option" data-action="quote">
            <svg viewBox="0 0 24 24"><path d="M6 17h3l2-4V7H5v6h3zm8 0h3l2-4V7h-6v6h3z"/></svg>
            Quote post
        </button>`;
    dd.querySelector('[data-action="boost"]').addEventListener('click', ev => {
        ev.stopPropagation(); dd.remove(); toggleBoost(id, boostBtn);
    });
    dd.querySelector('[data-action="quote"]').addEventListener('click', ev => {
        ev.stopPropagation(); dd.remove(); Compose.openQuote(id);
    });
    btn.appendChild(dd);
    // Close on outside click
    const close = (ev) => { if (!dd.contains(ev.target)) { dd.remove(); document.removeEventListener('click', close, true); } };
    setTimeout(() => document.addEventListener('click', close, true), 0);
}

function toggleNavUserMenu(e) {
    e.stopPropagation();
    const existing = document.querySelector('.nav-user-menu');
    if (existing) { existing.remove(); return; }
    const wrap = document.getElementById('nav-user');
    const dd = document.createElement('div');
    dd.className = 'nav-user-menu';
    dd.innerHTML = `
        <a href="#" onclick="event.preventDefault();this.closest('.nav-user-menu').remove();navigate('PROFILE')">
            <svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
            Profile
        </a>
        <a href="#" onclick="event.preventDefault();this.closest('.nav-user-menu').remove();navigate('FAVOURITES')">
            <svg viewBox="0 0 24 24"><path d="M16.5 3c-1.74 0-3.41.81-4.5 2.09C10.91 3.81 9.24 3 7.5 3 4.42 3 2 5.42 2 8.5c0 3.78 3.4 6.86 8.55 11.54L12 21.35l1.45-1.32C18.6 15.36 22 12.28 22 8.5 22 5.42 19.58 3 16.5 3z"/></svg>
            Favorites
        </a>
        <a href="#" onclick="event.preventDefault();this.closest('.nav-user-menu').remove();navigate('BOOKMARKS')">
            <svg viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"/></svg>
            Bookmarks
        </a>
        <div class="post-menu-divider"></div>
        <form method="post" action="/web/logout" style="margin:0">
            <input type="hidden" name="csrf" value="${esc(WCFG.webCsrf||'')}">
            <button type="submit" class="nav-menu-danger" style="width:100%">
                <svg viewBox="0 0 24 24"><path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/></svg>
                Sign out
            </button>
        </form>`;
    dd.addEventListener('click', ev => ev.stopPropagation());
    wrap.appendChild(dd);
    const close = (ev) => { if (!dd.contains(ev.target) && !wrap.contains(ev.target)) { dd.remove(); document.removeEventListener('click', close, true); } };
    setTimeout(() => document.addEventListener('click', close, true), 0);
}

function showPostMenu(e, id, bookmarked, isOwn, postUrl) {
    e.stopPropagation();
    document.querySelectorAll('.post-menu-dropdown,.repost-dropdown').forEach(d => d.remove());
    const btn = e.currentTarget;
    const dd = document.createElement('div');
    dd.className = 'post-menu-dropdown';
    dd.innerHTML = `
        <button class="repost-option" onclick="event.stopPropagation();this.closest('.post-menu-dropdown').remove();toggleBookmark('${escJsSq(id)}',null,${bookmarked ? 'true' : 'false'})">
            <svg viewBox="0 0 24 24"><path d="${bookmarked
                ? 'M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z'
                : 'M17 3H7c-1.1 0-1.99.9-1.99 2L5 21l7-3 7 3V5c0-1.1-.9-2-2-2zm0 15l-5-2.18L7 18V5h10v13z'}"/></svg>
            ${bookmarked ? 'Remove bookmark' : 'Bookmark'}
        </button>
        <button class="repost-option" onclick="event.stopPropagation();this.closest('.post-menu-dropdown').remove();copyText('${escJsSq(postUrl)}').then(()=>Toast.ok('Link copied')).catch(()=>Toast.err('Could not copy to clipboard.'))">
            <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
            Copy link
        </button>
        <a class="repost-option" href="${postUrl}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation();this.closest('.post-menu-dropdown').remove()">
            <svg viewBox="0 0 24 24"><path d="M19 19H5V5h7V3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
            Open original
        </a>
        ${isOwn ? `<div class="post-menu-divider"></div>
        <button class="repost-option" onclick="event.stopPropagation();this.closest('.post-menu-dropdown').remove();editStatus('${escJsSq(id)}')">
            <svg viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
            Edit
        </button>
        <button class="repost-option post-menu-danger" onclick="event.stopPropagation();this.closest('.post-menu-dropdown').remove();deleteStatus('${escJsSq(id)}')">
            <svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
            Delete
        </button>` : ''}`;
    btn.appendChild(dd);
    const close = (ev) => { if (!dd.contains(ev.target)) { dd.remove(); document.removeEventListener('click', close, true); } };
    setTimeout(() => document.addEventListener('click', close, true), 0);
}

async function toggleBoost(id, btn) {
    const active = btn.classList.contains('active');
    btn.disabled = true;
    try {
        const r = await Api.post('/api/v1/statuses/' + id + (active ? '/unreblog' : '/reblog'));
        const s = r.reblog || r;
        btn.classList.toggle('active', !!s.reblogged);
        const c = btn.querySelector('.action-count');
        if (c)                    c.textContent = s.reblogs_count > 0 ? s.reblogs_count : '';
        else if (s.reblogs_count > 0) btn.insertAdjacentHTML('beforeend', `<span class="action-count">${s.reblogs_count}</span>`);
    } catch (e) { Toast.err('Error reposting'); }
    btn.disabled = false;
}

async function toggleFav(id, btn) {
    const active = btn.classList.contains('active');
    btn.disabled = true;
    try {
        const s = await Api.post('/api/v1/statuses/' + id + (active ? '/unfavourite' : '/favourite'));
        btn.classList.toggle('active', !!s.favourited);
        const c = btn.querySelector('.action-count');
        if (c)                         c.textContent = s.favourites_count > 0 ? s.favourites_count : '';
        else if (s.favourites_count > 0) btn.insertAdjacentHTML('beforeend', `<span class="action-count">${s.favourites_count}</span>`);
    } catch (e) { Toast.err('Error reacting'); }
    btn.disabled = false;
}

async function submitPollVote(event, pollId, statusId) {
    event.preventDefault();
    event.stopPropagation();
    const form = event.currentTarget;
    const fd = new FormData(form);
    const choices = fd.getAll('choices[]');
    if (!choices.length) {
        Toast.err('Choose at least one option');
        return;
    }
    try {
        const poll = await Api.post('/api/v1/polls/' + encodeURIComponent(pollId) + '/votes', {choices});
        const box = form.closest('.poll-box');
        if (box) box.outerHTML = renderPoll(poll, statusId);
        Toast.ok('Vote submitted');
    } catch (e) {
        Toast.err(e.message || 'Error voting');
    }
}

async function toggleBookmark(id, btn, activeHint = null) {
    try {
        const active = activeHint !== null
            ? !!activeHint
            : btn?.classList.contains('active') || false;
        const s = await Api.post('/api/v1/statuses/' + id + (active ? '/unbookmark' : '/bookmark'));
        const now = !!s.bookmarked;
        btn?.classList.toggle('active', now);
        Toast.ok(now ? 'Bookmarked' : 'Bookmark removed');
    } catch (e) { Toast.err('Error saving'); }
}

async function toggleFollow(accountId, btn) {
    const following = btn.dataset.following === '1';
    btn.disabled = true;
    try {
        const rel = await Api.post('/api/v1/accounts/' + accountId + (following ? '/unfollow' : '/follow'));
        const isFollowing = !!rel.following;
        const isRequested = !!rel.requested && !isFollowing;
        btn.dataset.following = isFollowing ? '1' : '0';
        btn.dataset.requested = isRequested ? '1' : '0';
        btn.textContent = isFollowing ? 'Following' : (isRequested ? 'Requested' : 'Follow');
        btn.classList.toggle('following', isFollowing || isRequested);
        // Hide/show notify & lists buttons depending on follow state
        const actions = btn.closest('.profile-actions');
        actions?.querySelectorAll('.profile-follow-only').forEach(el => {
            el.style.display = isFollowing ? '' : 'none';
        });
    } catch (e) { Toast.err('Error following'); }
    btn.disabled = false;
}

async function toggleNotify(accountId, btn) {
    const notifying = btn.dataset.notifying === '1';
    btn.disabled = true;
    try {
        const rel = await Api.post('/api/v1/accounts/' + accountId + '/follow', {notify: !notifying});
        const now = !!rel.notifying;
        btn.dataset.notifying = now ? '1' : '0';
        btn.title = now ? 'Disable post notifications' : 'Enable post notifications';
        btn.classList.toggle('active', now);
        // swap bell icon path
        const bellFull = 'M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6V11c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z';
        const bellOutline = 'M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6V11c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2zM17 13.58V11c0-2.28-1.47-4.22-3.54-4.78C11.02 5.65 9 7.32 9 9.5c0 .39.08.76.19 1.12L17 13.58z';
        btn.querySelector('path')?.setAttribute('d', now ? bellFull : bellOutline);
    } catch (e) { Toast.err('Error updating notifications'); }
    btn.disabled = false;
}

async function showListsMenu(accountId, btn) {
    // close any open menu first
    document.querySelector('.lists-menu-popover')?.remove();

    const menu = document.createElement('div');
    menu.className = 'lists-menu-popover';
    menu.innerHTML = '<div class="lists-menu-loading">Loading…</div>';

    // position below button
    const rect = btn.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom;
    if (spaceBelow >= 120) {
        menu.style.top  = (rect.bottom + 4) + 'px';
        menu.style.left = rect.left + 'px';
    } else {
        menu.style.bottom = (window.innerHeight - rect.top + 4) + 'px';
        menu.style.left   = rect.left + 'px';
    }
    document.body.appendChild(menu);

    // close on outside click
    setTimeout(() => {
        document.addEventListener('click', function handler(e) {
            if (!menu.contains(e.target) && e.target !== btn) {
                menu.remove();
                document.removeEventListener('click', handler);
            }
        });
    }, 10);

    try {
        const [allLists, accountLists] = await Promise.all([
            Api.get('/api/v1/lists'),
            Api.get('/api/v1/accounts/' + accountId + '/lists'),
        ]);
        if (!allLists.length) {
            menu.innerHTML = '<div class="lists-menu-empty">No lists created</div>';
            return;
        }
        const inIds = new Set(accountLists.map(l => l.id));
        menu.innerHTML = allLists.map(l => `
            <label class="lists-menu-item">
                <input type="checkbox" ${inIds.has(l.id) ? 'checked' : ''}
                    data-list-id="${esc(l.id)}" data-acct-id="${esc(accountId)}">
                ${esc(l.title)}
            </label>`).join('');
        menu.querySelectorAll('input[type=checkbox]').forEach(cb => {
            cb.addEventListener('change', async () => {
                cb.disabled = true;
                const lid = cb.dataset.listId;
                const aid = cb.dataset.acctId;
                try {
                    if (cb.checked) await Api.post('/api/v1/lists/' + lid + '/accounts', {account_ids: [aid]});
                    else            await Api.del('/api/v1/lists/'  + lid + '/accounts', {account_ids: [aid]});
                } catch (e) {
                    cb.checked = !cb.checked;
                    Toast.err('Error updating list');
                }
                cb.disabled = false;
            });
        });
    } catch (e) {
        menu.innerHTML = '<div class="lists-menu-error">Error loading</div>';
    }
}

async function deleteStatus(id) {
    const card = document.querySelector(`.status-card[data-id="${id}"]`);
    if (!card) return;
    card.style.opacity    = '.35';
    card.style.transition = 'opacity .2s';
    let cancelled = false;
    const c = document.getElementById('toast-container');
    let toastEl = null;
    if (c) {
        toastEl = document.createElement('div');
        toastEl.className = 'toast';
        toastEl.innerHTML = 'Post deleted. <button class="toast-undo">Undo</button>';
        c.appendChild(toastEl);
        toastEl.querySelector('.toast-undo').addEventListener('click', () => {
            cancelled = true;
            card.style.opacity = '';
            toastEl.remove();
        });
    }
    await new Promise(r => setTimeout(r, 4500));
    toastEl?.remove();
    if (cancelled) return;
    try {
        await Api.del('/api/v1/statuses/' + id);
        card.remove();
    } catch (e) {
        card.style.opacity = '';
        Toast.err('Error deleting: ' + e.message);
    }
}

function handleCardClick(e, id) {
    // Ignore clicks on interactive elements — they have their own handlers
    if (e.target.closest('button, a, input, .avatar, .s-name, .media-item, .sensitive-overlay, .link-card')) return;
    navigate('THREAD', id);
}

function toggleCWContent(btn) {
    // cwBar is a sibling of cw-wrapper, not a parent — use nextElementSibling
    const wrap    = btn.closest('.cw-bar')?.nextElementSibling;
    const content = wrap?.querySelector('.cw-content');
    if (!content) return;
    const hidden = content.style.display === 'none';
    content.style.display = hidden ? '' : 'none';
    btn.textContent = hidden ? 'Hide content' : 'Show more';
}

async function approveFollowRequest(accountId, btn) {
    try {
        await Api.post('/api/v1/follow_requests/' + accountId + '/authorize');
        btn.closest('.notif-card')?.remove();
    } catch (e) { Toast.err('Error: ' + e.message); }
}

async function rejectFollowRequest(accountId, btn) {
    try {
        await Api.post('/api/v1/follow_requests/' + accountId + '/reject');
        btn.closest('.notif-card')?.remove();
    } catch (e) { Toast.err('Error: ' + e.message); }
}

async function editStatus(id) {
    try {
        const s = await Api.get('/api/v1/statuses/' + id + '/source');
        const editText = (s.content_type === 'text/html' && typeof s.text_plain === 'string')
            ? s.text_plain
            : s.text;
        Compose.openEdit(
            id,
            editText,
            s.spoiler_text || '',
            s.visibility || 'public',
            s.poll || null,
            s.expires_at || null,
            s.media_ids || [],
            s.media_attachments || []
        );
    } catch (e) { Toast.err('Error loading post: ' + e.message); }
}

// ── Compose ────────────────────────────────────────────────────────────────
const Compose = {
    _replyToId: null,
    _editId:    null,
    _editExpiresAt: null,
    _editHasPoll: false,
    _mediaIds:  [],
    _prevFocus: null,

    openDM(acct) {
        this.open(null, null, '@' + acct + ' ');
        document.getElementById('vis-select').value = 'direct';
        document.getElementById('expire-select').value = '';
    },

    open(replyToId = null, replyToAcct = null, prefillText = null) {
        this._editId    = null;
        this._editExpiresAt = null;
        this._editHasPoll = false;
        this._replyToId = replyToId;
        this._mediaIds  = [];
        this._prevFocus = document.activeElement;
        document.getElementById('vis-select').value  = USERPREFS.defaultVisibility || 'public';
        this.syncExpireSelectOptions();
        document.getElementById('expire-select').value = USERPREFS.defaultExpireAfter ? String(USERPREFS.defaultExpireAfter) : '';
        document.getElementById('compose-text').value = prefillText ?? (replyToAcct ? '@' + replyToAcct + ' ' : '');
        const rp = document.getElementById('reply-preview');
        rp.style.display = replyToId ? '' : 'none';
        if (replyToId) rp.textContent = 'Replying to @' + (replyToAcct || '');
        document.getElementById('compose-title').textContent = replyToId ? 'Reply' : 'New post';
        document.getElementById('media-previews').innerHTML  = '';
        document.getElementById('cw-input').value            = '';
        document.getElementById('cw-input').style.display    = 'none';
        this.resetPoll();
        this.updatePollToggle();
        document.getElementById('compose-avatar').src = WCFG.myAvatar || '';
        document.getElementById('compose-modal').classList.add('open');
        setTimeout(() => document.getElementById('compose-text').focus(), 50);
        this.updateCount();
    },

    openEdit(id, text, cw, visibility = 'public', poll = null, expiresAt = null, mediaIds = [], mediaAttachments = []) {
        this._editId    = id;
        this._editExpiresAt = expiresAt || null;
        this._editHasPoll = !!poll;
        this._replyToId = null;
        this._mediaIds  = Array.isArray(mediaIds) ? [...mediaIds] : [];
        this._prevFocus = document.activeElement;
        document.getElementById('compose-text').value        = text;
        document.getElementById('cw-input').value            = cw;
        document.getElementById('cw-input').style.display    = cw ? '' : 'none';
        document.getElementById('vis-select').value          = visibility || 'public';
        document.getElementById('compose-title').textContent = 'Edit post';
        this.syncExpireSelectOptions();
        document.getElementById('expire-select').value       = expiresAt ? '__keep__' : '';
        document.getElementById('reply-preview').style.display = 'none';
        document.getElementById('media-previews').innerHTML  = (Array.isArray(mediaAttachments) ? mediaAttachments : []).map(media => {
            const url = esc(media.preview_url || media.url || '');
            const mid = esc(media.id || '');
            return `<div class="media-thumb" data-media-id="${mid}"><img src="${url}" alt=""><button onclick="Compose.removeMedia('${escJsSq(mid)}',this)" type="button" aria-label="Remove">✕</button></div>`;
        }).join('');
        this.resetPoll();
        if (poll) {
            const box = document.getElementById('compose-poll');
            const opts = Array.isArray(poll.options) ? poll.options : [];
            box.style.display = '';
            this.setPollOptions(opts.map(opt => ({title: opt})));
            document.getElementById('compose-poll-multiple').checked = !!poll.multiple;
            const note = document.getElementById('compose-poll-note');
            if (note) {
                note.style.display = '';
                note.textContent = 'Poll editing is not supported. You can review the current options, but changes will not be saved.';
            }
            box.querySelectorAll('.compose-poll-option').forEach(input => input.disabled = true);
            document.getElementById('compose-poll-multiple').disabled = true;
            document.getElementById('compose-poll-expiration').disabled = true;
            document.getElementById('compose-poll-add').disabled = true;
        }
        this.updatePollToggle();
        document.getElementById('compose-avatar').src = WCFG.myAvatar || '/img/avatar.svg';
        document.getElementById('compose-modal').classList.add('open');
        setTimeout(() => document.getElementById('compose-text').focus(), 50);
        this.updateCount();
    },

    expireSelectValueForIso(expiresAt) {
        if (!expiresAt) return '';
        const ts = Date.parse(expiresAt);
        if (!Number.isFinite(ts)) return '';
        const remaining = Math.max(0, Math.round((ts - Date.now()) / 1000));
        const options = [3600, 21600, 86400, 604800, 2592000];
        const match = options.find(v => Math.abs(v - remaining) <= Math.max(1800, Math.round(v * 0.15)));
        return match ? String(match) : '';
    },

    syncExpireSelectOptions() {
        const select = document.getElementById('expire-select');
        if (!select) return;
        select.querySelector('option[value="__keep__"]')?.remove();
        if (this._editId && this._editExpiresAt) {
            const option = document.createElement('option');
            option.value = '__keep__';
            option.textContent = 'Keep current expiry (' + formatDate(this._editExpiresAt) + ')';
            select.insertBefore(option, select.firstChild);
        }
    },

    openReply(statusId, acct) { this.open(statusId, acct); },

    async openQuote(statusId) {
        try {
            const s = await Api.get('/api/v1/statuses/' + statusId);
            const url = s.url || s.uri;
            this.open(null, null, '\n\n' + url);
            document.getElementById('compose-title').textContent = 'Quote post';
            const rp = document.getElementById('reply-preview');
            rp.style.display = '';
            rp.textContent = 'Quoting @' + (s.account?.acct || '');
        } catch { this.open(null, null, ''); Toast.err('Error loading post'); }
    },

    close() {
        document.getElementById('compose-modal').classList.remove('open');
        this._replyToId = null;
        this._editId    = null;
        this._editExpiresAt = null;
        this._editHasPoll = false;
        this._mediaIds  = [];
        document.getElementById('compose-text').value         = '';
        document.getElementById('cw-input').value             = '';
        document.getElementById('cw-input').style.display     = 'none';
        this.syncExpireSelectOptions();
        document.getElementById('expire-select').value        = USERPREFS.defaultExpireAfter ? String(USERPREFS.defaultExpireAfter) : '';
        document.getElementById('media-previews').innerHTML   = '';
        this.resetPoll();
        this.updatePollToggle();
        this._prevFocus?.focus();
        this._prevFocus = null;
    },

    toggleCW() {
        const cw = document.getElementById('cw-input');
        cw.style.display = cw.style.display === 'none' ? '' : 'none';
        if (cw.style.display !== 'none') cw.focus();
    },

    updateCount() {
        const len = document.getElementById('compose-text')?.value?.length ?? 0;
        const rem = WCFG.postChars - len;
        const el  = document.getElementById('char-count');
        if (!el) return;
        el.textContent = rem;
        el.className   = rem < 0 ? 'over' : rem < 20 ? 'warn' : '';
    },

    async handleMedia(input) {
        const files = Array.from(input.files).slice(0, 4 - this._mediaIds.length);
        input.value = '';
        await Promise.all(files.map(async file => {
            const fd = new FormData();
            fd.append('file', file);
            try {
                const media = await Api._fetch('POST', '/api/v2/media', fd);
                this._mediaIds.push(media.id);
                const url = esc(media.preview_url || media.url);
                document.getElementById('media-previews').insertAdjacentHTML('beforeend',
                    `<div class="media-thumb" data-media-id="${esc(media.id)}"><img src="${url}" alt=""><button onclick="Compose.removeMedia('${escJsSq(media.id)}',this)" type="button" aria-label="Remove">✕</button></div>`);
            } catch (e) { Toast.err('Error loading file: ' + e.message); }
        }));
    },

    removeMedia(id, btn) {
        this._mediaIds = this._mediaIds.filter(i => i !== id);
        btn.closest('.media-thumb')?.remove();
    },

    updatePollToggle() {
        const btn = document.getElementById('poll-toggle-btn');
        if (!btn) return;
        const disabled = !!this._editId;
        btn.disabled = disabled;
        btn.title = disabled
            ? (this._editHasPoll ? 'Poll editing is not supported' : 'Polls cannot be added while editing')
            : 'Add poll';
        btn.style.opacity = disabled ? '.45' : '';
        btn.style.cursor = disabled ? 'not-allowed' : '';
    },

    togglePoll() {
        if (this._editId) {
            Toast.err(this._editHasPoll ? 'Editing polls is not supported' : 'Polls cannot be added while editing');
            return;
        }
        const box = document.getElementById('compose-poll');
        const next = box.style.display === 'none' ? '' : 'none';
        box.style.display = next;
        if (next !== 'none' && !document.querySelectorAll('.compose-poll-option').length) {
            this.setPollOptions([{title:''},{title:''}]);
        }
    },

    resetPoll() {
        document.getElementById('compose-poll').style.display = 'none';
        document.getElementById('compose-poll-multiple').checked = false;
        document.getElementById('compose-poll-multiple').disabled = false;
        document.getElementById('compose-poll-expiration').value = '86400';
        document.getElementById('compose-poll-expiration').disabled = false;
        document.getElementById('compose-poll-add').disabled = false;
        const note = document.getElementById('compose-poll-note');
        if (note) {
            note.style.display = 'none';
            note.textContent = '';
        }
        this.setPollOptions([{title:''},{title:''}]);
    },

    setPollOptions(options) {
        const wrap = document.getElementById('compose-poll-options');
        wrap.innerHTML = '';
        options.slice(0, 4).forEach((opt, idx) => {
            wrap.insertAdjacentHTML('beforeend', `<input class="compose-poll-option" type="text" placeholder="Option ${idx + 1}" maxlength="50" value="${esc(opt.title || opt)}">`);
        });
    },

    addPollOption() {
        const wrap = document.getElementById('compose-poll-options');
        const count = wrap.querySelectorAll('.compose-poll-option').length;
        if (count >= 4) return;
        wrap.insertAdjacentHTML('beforeend', `<input class="compose-poll-option" type="text" placeholder="Option ${count + 1}" maxlength="50">`);
    },

    async submit() {
        const text = document.getElementById('compose-text').value;
        const cw   = document.getElementById('cw-input').value.trim();
        const vis  = document.getElementById('vis-select').value;
        const expireRaw = document.getElementById('expire-select').value || '';
        const expireAfter = Number(expireRaw || 0);
        const pollOpen = document.getElementById('compose-poll').style.display !== 'none';
        const pollOptions = Array.from(document.querySelectorAll('.compose-poll-option')).map(i => i.value.trim()).filter(Boolean);
        if (!text.trim() && !this._mediaIds.length && !pollOpen) return;
        if (pollOpen && this._mediaIds.length) { Toast.err('Polls cannot include media'); return; }
        if (pollOpen && pollOptions.length < 2) { Toast.err('A poll needs at least two options'); return; }
        const submitBtn   = document.getElementById('compose-submit');
        const origLabel   = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = this._editId ? 'Saving…' : 'Posting…';
        try {
            const body = {status: text, visibility: vis};
            if (cw)                    body.spoiler_text   = cw;
            if (this._replyToId)       body.in_reply_to_id = this._replyToId;
            if (this._mediaIds.length) body.media_ids      = this._mediaIds;
            if (USERPREFS.defaultSensitive && this._mediaIds.length) body.sensitive = true;
            if (this._editId) {
                if (expireRaw === '__keep__') {
                    // Keep the current absolute expiry unchanged.
                } else {
                    body.expires_in = expireAfter > 0 ? expireAfter : 0;
                }
            }
            else if (expireAfter > 0) body.expires_in = expireAfter;
            if (pollOpen && !this._editId) {
                body.poll = {
                    options: pollOptions,
                    multiple: document.getElementById('compose-poll-multiple').checked,
                    expires_in: Number(document.getElementById('compose-poll-expiration').value || 86400),
                };
            }
            if (this._editId) {
                const s = await Api.put('/api/v1/statuses/' + this._editId, body);
                this.close();
                const cards = Array.from(document.querySelectorAll(`.status-card[data-id="${s.id}"]`));
                if (cards.length) {
                    const tmp = document.createElement('div');
                    tmp.innerHTML = renderStatus(s);
                    const fresh = tmp.firstElementChild;
                    cards.forEach((card, index) => {
                        card.replaceWith(index === 0 ? fresh : fresh.cloneNode(true));
                    });
                } else if (WCFG.view === 'THREAD') {
                    navigate('THREAD', s.id);
                } else if (WCFG.view === 'PROFILE' && String(WCFG.viewId || '') === String(WCFG.myId || '')) {
                    navigate('PROFILE', WCFG.myId);
                }
                Toast.ok('Post edited.');
            } else {
                const s = await Api.post('/api/v1/statuses', body);
                this.close();
                await refreshAfterCreate(s);
            }
        } catch (e) { Toast.err('Error posting: ' + e.message); }
        submitBtn.disabled    = false;
        submitBtn.textContent = origLabel;
    },
};

// ── Lightbox ───────────────────────────────────────────────────────────────
const Lightbox = {
    open(src, alt = '') {
        document.getElementById('lb-img').src = src;
        document.getElementById('lb-img').alt = alt;
        document.getElementById('lightbox').classList.add('open');
    },
    close() {
        document.getElementById('lightbox').classList.remove('open');
        document.getElementById('lb-img').src = '';
    },
};

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    applyAppearancePrefs();
    // Nav user info
    const av = document.getElementById('nav-avatar');
    if (av) av.src = WCFG.myAvatar;
    const nn = document.getElementById('nav-name');
    if (nn) nn.textContent = WCFG.myDisplayName || WCFG.myUsername;
    const na = document.getElementById('nav-acct');
    if (na) na.textContent = '@' + WCFG.myUsername + '@' + WCFG.domain;
    // (nav-profile-link removed — account menu handles navigation now)

    // Nav link SPA click handling
    document.querySelectorAll('.nav-link[data-view]').forEach(a => {
        a.addEventListener('click', e => {
            e.preventDefault();
            const view = a.dataset.view;
            const id   = (view === 'PROFILE') ? WCFG.myId : null;
            // Bluesky behavior: clicking the already-active nav scrolls to top
            if (view === WCFG.view && (view !== 'PROFILE' || id === WCFG.viewId)) {
                window.scrollTo({top: 0, behavior: 'smooth'});
                if (view === 'HOME') showHome(_homeTab);
                return;
            }
            navigate(view, id);
        });
    });

    // Bottom nav SPA click handling
    document.querySelectorAll('.bn-item[data-view]').forEach(a => {
        a.addEventListener('click', e => {
            e.preventDefault();
            const view = a.dataset.view;
            const id   = (view === 'PROFILE') ? WCFG.myId : null;
            if (view === WCFG.view && (view !== 'PROFILE' || id === WCFG.viewId)) {
                window.scrollTo({top: 0, behavior: 'smooth'});
                if (view === 'HOME') showHome(_homeTab);
                return;
            }
            navigate(view, id);
        });
    });
    // Set bottom nav profile link
    const bnProfile = document.getElementById('bn-profile');
    if (bnProfile) { bnProfile.href = '/web/profile/' + WCFG.myId; }

    // Bottom sheet ("More") SPA click handling
    document.querySelectorAll('.bs-item[data-view]').forEach(a => {
        a.addEventListener('click', e => {
            e.preventDefault();
            const view = a.dataset.view;
            const id   = (view === 'PROFILE') ? WCFG.myId : null;
            navigate(view, id);
        });
    });

    // Compose button
    document.querySelector('.compose-btn')?.addEventListener('click', () => Compose.open());

    const rightSearchInput = document.getElementById('right-search-input');
    let _rightSearchDebounce = null;
    if (rightSearchInput) {
        rightSearchInput.addEventListener('focus', () => {
            if (rightSearchInput.value.trim()) {
                openExploreSearch(rightSearchInput.value.trim());
            }
        });
        rightSearchInput.addEventListener('input', e => {
            clearTimeout(_rightSearchDebounce);
            const q = e.target.value.trim();
            if (!q) return;
            _rightSearchDebounce = setTimeout(() => openExploreSearch(q), 240);
        });
        rightSearchInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const q = rightSearchInput.value.trim();
                if (q) openExploreSearch(q);
            }
        });
    }

    // Popstate — restore cached view if available, otherwise reload
    window.addEventListener('popstate', e => {
        const state = e.state;
        const view  = state?.view || 'HOME';
        const id    = state?.id   || null;

        WCFG.view   = view;
        WCFG.viewId = id;

        // Restore _homeTab BEFORE cache lookup (cache key depends on it)
        if (view === 'HOME' && state?.homeTab) _homeTab = state.homeTab;
        if (view === 'HOME') { updateNewPostsBtn(); }

        setActiveNav(view);

        // Try to restore cached content + scroll position first
        if (_restoreCachedView(view, id)) {
            // If returning to HOME, refresh tab bar active state (bar is outside col-content)
            if (view === 'HOME') _renderHomeTabBar();
            return;
        }

        // Cache miss — full reload
        dispatchView(view, id);
    });

    // Compose textarea count
    document.getElementById('compose-text')?.addEventListener('input', () => Compose.updateCount());

    // Compose modal — only closes via X button or Escape (like Bluesky)
    // Compose modal keyboard close (already handled by Escape in keydown)

    // Lightbox close
    document.getElementById('lightbox')?.addEventListener('click', e => {
        if (e.target.id === 'lightbox' || e.target.id === 'lb-close') Lightbox.close();
    });
    document.addEventListener('click', e => {
        const img = e.target.closest?.('.media-item img[data-full-src]');
        if (!img) return;
        e.preventDefault();
        e.stopPropagation();
        Lightbox.open(img.dataset.fullSrc || img.src, img.dataset.alt || img.alt || '');
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { Compose.close(); Lightbox.close(); }
        const notTyping = !e.ctrlKey && !e.metaKey && !e.target.matches('input,textarea,select,button');
        if (!notTyping) return;
        if (e.key === 'n') { Compose.open(); return; }
        if (e.key === 'j' || e.key === 'k') {
            const cards = Array.from(document.querySelectorAll('#col-content .status-card'));
            if (!cards.length) return;
            const idx = _focusedCard ? cards.indexOf(_focusedCard) : -1;
            focusCard(e.key === 'j' ? cards[Math.min(idx + 1, cards.length - 1)] : cards[Math.max(idx - 1, 0)]);
        }
    });

    await loadReadingPrefs();

    // Initial view
    setActiveNav(WCFG.view);
    dispatchView(WCFG.view, WCFG.viewId);
    loadRightCol();

    // Compose media input
    document.getElementById('media-input')?.addEventListener('change', function () { Compose.handleMedia(this); });

    // CW toggle button
    document.getElementById('cw-toggle-btn')?.addEventListener('click', () => Compose.toggleCW());
    document.getElementById('poll-toggle-btn')?.addEventListener('click', () => Compose.togglePoll());
    document.getElementById('compose-poll-add')?.addEventListener('click', () => Compose.addPollOption());

    // Init char count
    Compose.updateCount();

    // Pull-to-refresh (mobile)
    let _ptStart = 0, _ptDist = 0, _ptPulling = false;
    const PTR_THRESHOLD = 72;
    const ptrEl = document.getElementById('ptr-indicator');
    document.addEventListener('touchstart', e => {
        if (document.documentElement.scrollTop === 0 && document.scrollingElement?.scrollTop === 0) {
            _ptStart = e.touches[0].clientY; _ptPulling = true;
        }
    }, {passive: true});
    document.addEventListener('touchmove', e => {
        if (!_ptPulling) return;
        _ptDist = Math.max(0, e.touches[0].clientY - _ptStart);
        if (ptrEl && _ptDist > 0) {
            const pct = Math.min(_ptDist / PTR_THRESHOLD, 1);
            ptrEl.style.opacity   = String(pct);
            ptrEl.textContent     = _ptDist >= PTR_THRESHOLD ? '↑ Release to refresh' : '↓ Pull to refresh';
        }
    }, {passive: true});
    document.addEventListener('touchend', () => {
        if (!_ptPulling) return;
        _ptPulling = false;
        if (ptrEl) { ptrEl.style.opacity = '0'; ptrEl.textContent = '↓ Pull to refresh'; }
        if (_ptDist >= PTR_THRESHOLD) dispatchView(WCFG.view, WCFG.viewId || null);
        _ptDist = 0;
    }, {passive: true});

    // ── Content link interceptor ───────────────────────────────────────────
    // Intercepts clicks on hashtag and mention links inside post content,
    // navigating within the SPA instead of opening external servers.
    document.addEventListener('click', e => {
        const a = e.target.closest('.s-content a, .notif-excerpt a');
        if (!a) return;
        const href = a.href || '';
        if (!href.startsWith('http')) return;

        // Hashtag: URL contains /tags/ or /tag/, or element has rel="tag"
        const tagM = href.match(/\/tags?\/([^/?#]+)/i);
        if (tagM || a.rel === 'tag') {
            e.preventDefault();
            const tag = tagM ? decodeURIComponent(tagM[1]) : a.textContent.replace(/^#/, '').trim();
            if (tag) navigate('TAG_TIMELINE', tag);
            return;
        }

        // Mention: has class "mention" (but not hashtag)
        if (a.classList.contains('mention') && !a.classList.contains('hashtag')) {
            e.preventDefault();
            // Extract acct from URL: /@user or /users/user → user@domain
            const url   = new URL(href);
            const path  = url.pathname;
            const user  = path.match(/^\/@?([^/]+)$/)?.[1] ?? path.match(/\/users\/([^/]+)$/)?.[1];
            const acct  = user ? user + '@' + url.hostname : '';
            if (acct) {
                Api.get('/api/v1/accounts/lookup', {acct}).then(acc => {
                    if (acc?.id) navigate('PROFILE', acc.id);
                }).catch(() => window.open(href, '_blank', 'noopener'));
            } else {
                window.open(href, '_blank', 'noopener');
            }
            return;
        }

        // All other links in content open externally
        e.preventDefault();
        window.open(href, '_blank', 'noopener,noreferrer');
    });

    // Start real-time streaming + check for unread notifications on load
    startStreaming();
    checkUnreadNotifications();

    // Intent compose: open compose box pre-filled if launched via /web/intent/compose?text=
    if (WCFG.composeText) setTimeout(() => Compose.open(null, null, WCFG.composeText), 300);
});
JS;
    }
}
