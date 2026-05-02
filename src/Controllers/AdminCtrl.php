<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Models\{AdminModel, UserModel, DB};

/**
 * Administration panel — /admin/*
 * All routes verify authentication via the PHP session.
 */
class AdminCtrl
{
    private function generatedConfigPath(): string
    {
        return ROOT . '/storage/config.generated.php';
    }

    private function readGeneratedConfig(): array
    {
        $path = $this->generatedConfigPath();
        if (!is_file($path)) {
            return [];
        }
        $config = require $path;
        return is_array($config) ? $config : [];
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

    // ── Brute-force protection ────────────────────────────────

    private function checkRateLimit(string $ip): bool
    {
        try {
            DB::pdo()->exec("CREATE TABLE IF NOT EXISTS admin_login_attempts (ip TEXT NOT NULL, ts INTEGER NOT NULL)");
            $c = (int)(DB::one(
                "SELECT COUNT(*) c FROM admin_login_attempts WHERE ip=? AND ts>?",
                [$ip, time() - 900]
            )['c'] ?? 0);
            return $c >= 10;
        } catch (\Throwable) { return false; }
    }

    private function recordFailedAttempt(string $ip): void
    {
        try {
            DB::run("INSERT INTO admin_login_attempts (ip, ts) VALUES (?, ?)", [$ip, time()]);
            DB::run("DELETE FROM admin_login_attempts WHERE ts<?", [time() - 7200]);
        } catch (\Throwable) {}
    }

    // ── Auth ─────────────────────────────────────────────────

    public function login(array $p): void
    {
        AdminModel::startSession();
        if (AdminModel::isLoggedIn()) { $this->redirect('/admin'); }

        // Ensure a CSRF token exists before rendering the form or handling POST.
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(16));
        }

        $error = '';
        $ip    = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $csrf = $_POST['csrf'] ?? '';
            if (!$csrf || !hash_equals($_SESSION['csrf'], $csrf)) {
                $error = 'Invalid request.';
            } elseif ($this->checkRateLimit($ip)) {
                $error = 'Too many failed attempts. Wait 15 minutes.';
            } elseif (AdminModel::login($_POST['username'] ?? '', $_POST['password'] ?? '')) {
                $this->redirect('/admin');
            } else {
                sleep(1);
                $this->recordFailedAttempt($ip);
                $error = 'Invalid credentials or missing administrator permissions.';
            }
        }
        // Rotate token after each use so it cannot be reused
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
        $this->html($this->loginPage($_SESSION['csrf'], $error));
    }

    public function logout(array $p): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            $this->redirect('/admin');
        }
        $this->requireAuth();
        $this->requirePost();
        AdminModel::logout();
        $this->redirect('/admin/login');
    }

    // ── Dashboard ─────────────────────────────────────────────

    public function dashboard(array $p): void
    {
        $this->requireAuth();
        $stats = AdminModel::dashboardStats();
        $this->html($this->layout('Dashboard', $this->dashboardContent($stats)));
    }

    public function actionLog(array $p): void
    {
        $this->requireAuth();
        $page = max(1, (int)($_GET['page'] ?? 1));
        $data = AdminModel::actionLog($page);
        $this->html($this->layout('Action Log', $this->actionLogContent($data)));
    }

    // ── Users ────────────────────────────────────────────────

    public function users(array $p): void
    {
        $this->requireAuth();
        $page   = max(1, (int)($_GET['page'] ?? 1));
        $q      = trim($_GET['q'] ?? '');
        $filter = $_GET['filter'] ?? 'all';
        $data   = AdminModel::listUsers($page, $q, $filter);
        $this->html($this->layout('Users', $this->usersContent($data, $q, $filter)));
    }

    public function createUser(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();

        $username = trim((string)($_POST['username'] ?? ''));
        $email = trim((string)($_POST['email'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $displayName = trim((string)($_POST['display_name'] ?? ''));
        $isAdmin = !empty($_POST['is_admin']) ? 1 : 0;
        $isBot = !empty($_POST['is_bot']) ? 1 : 0;

        if ($username === '' || $email === '' || $password === '') {
            $this->flash('error', 'Username, email, and password are required.');
            $this->redirect('/admin/users');
        }
        if (!preg_match('/^\w{1,30}$/', $username)) {
            $this->flash('error', 'Invalid username. Use letters, numbers, and underscore only, up to 30 characters.');
            $this->redirect('/admin/users');
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->flash('error', 'Invalid email address.');
            $this->redirect('/admin/users');
        }
        if (strlen($password) < 8) {
            $this->flash('error', 'Password must be at least 8 characters long.');
            $this->redirect('/admin/users');
        }
        if (UserModel::byUsernameAny($username)) {
            $this->flash('error', 'That username is already in use.');
            $this->redirect('/admin/users');
        }
        if (UserModel::byEmailAny($email)) {
            $this->flash('error', 'That email address is already in use.');
            $this->redirect('/admin/users');
        }

        UserModel::create([
            'username' => $username,
            'email' => $email,
            'password' => $password,
            'display_name' => $displayName !== '' ? $displayName : $username,
            'is_admin' => $isAdmin,
            'is_bot' => $isBot,
        ]);
        $admin = AdminModel::currentAdmin();
        AdminModel::logAction(
            $admin['id'] ?? null,
            'user.create',
            'user',
            strtolower($username),
            'Created a user account.',
            ['username' => strtolower($username), 'email' => strtolower($email), 'is_admin' => $isAdmin, 'is_bot' => $isBot]
        );

        $this->flash('success', 'User created successfully.');
        $this->redirect('/admin/users');
    }

    public function updateUser(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();

        $id = (string)($p['id'] ?? '');
        $target = UserModel::byId($id);
        $admin = AdminModel::currentAdmin();
        if (!$target) {
            $this->flash('error', 'User not found.');
            $this->redirect('/admin/users');
        }

        $email = trim((string)($_POST['email'] ?? ''));
        $displayName = trim((string)($_POST['display_name'] ?? ''));
        $newPassword = (string)($_POST['password'] ?? '');
        $isAdmin = !empty($_POST['is_admin']) ? 1 : 0;
        $isBot = !empty($_POST['is_bot']) ? 1 : 0;
        $isLocked = !empty($_POST['is_locked']) ? 1 : 0;

        if ($email === '') {
            $this->flash('error', 'Email is required.');
            $this->redirect('/admin/users');
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->flash('error', 'Invalid email address.');
            $this->redirect('/admin/users');
        }
        $existingByEmail = UserModel::byEmailAny($email);
        if ($existingByEmail && $existingByEmail['id'] !== $target['id']) {
            $this->flash('error', 'That email address is already in use.');
            $this->redirect('/admin/users');
        }
        if ($newPassword !== '' && strlen($newPassword) < 8) {
            $this->flash('error', 'New password must be at least 8 characters long.');
            $this->redirect('/admin/users');
        }
        if ($admin && $target['id'] === $admin['id'] && !$isAdmin) {
            $this->flash('error', 'You cannot remove administrator access from your own account.');
            $this->redirect('/admin/users');
        }

        $updates = [
            'email' => strtolower($email),
            'display_name' => $displayName !== '' ? $displayName : $target['username'],
            'is_admin' => $isAdmin,
            'is_bot' => $isBot,
            'is_locked' => $isLocked,
        ];
        if ($newPassword !== '') {
            $updates['password'] = password_hash($newPassword, PASSWORD_BCRYPT);
        }

        UserModel::update($target['id'], $updates);
        AdminModel::logAction(
            $admin['id'] ?? null,
            'user.update',
            'user',
            $target['id'],
            'Updated user settings.',
            [
                'username' => $target['username'],
                'email' => strtolower($email),
                'is_admin' => $isAdmin,
                'is_bot' => $isBot,
                'is_locked' => $isLocked,
                'password_reset' => $newPassword !== '',
            ]
        );
        $this->flash('success', 'User updated successfully.');
        $this->redirect('/admin/users');
    }

    public function userAction(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $action = $p['action'] ?? '';
        $id     = $p['id']     ?? '';
        $admin  = AdminModel::currentAdmin();

        if ($id === $admin['id'] && in_array($action, ['suspend', 'delete'])) {
            $this->flash('error', 'You cannot suspend or delete your own account.');
            $this->redirect('/admin/users');
        }

        match ($action) {
            'suspend'    => AdminModel::suspendUser($id, true),
            'unsuspend'  => AdminModel::suspendUser($id, false),
            'toggle_admin'=> AdminModel::toggleAdmin($id),
            'delete'     => AdminModel::deleteUser($id),
            default      => null,
        };

        AdminModel::logAction(
            $admin['id'] ?? null,
            'user.' . $action,
            'user',
            (string)$id,
            'Applied an administrative user action.',
            ['action' => $action]
        );

        $this->flash('success', 'Action completed successfully.');
        $this->redirect('/admin/users');
    }

    public function media(array $p): void
    {
        $this->requireAuth();
        $page = max(1, (int)($_GET['page'] ?? 1));
        $q = trim((string)($_GET['q'] ?? ''));
        $type = (string)($_GET['type'] ?? 'all');
        $orphans = !empty($_GET['orphans']);
        $data = AdminModel::listMedia($page, $q, $type, $orphans);
        $this->html($this->layout('Media', $this->mediaContent($data, $q, $type, $orphans)));
    }

    public function mediaDelete(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $admin = AdminModel::currentAdmin();
        $deleted = AdminModel::deleteMedia((string)($p['id'] ?? ''));
        if (!$deleted) {
            $this->flash('error', 'Media file not found.');
            $this->redirect('/admin/media');
        }
        AdminModel::logAction(
            $admin['id'] ?? null,
            'media.delete',
            'media',
            (string)$deleted['id'],
            'Deleted a media attachment.',
            ['url' => $deleted['url'], 'type' => $deleted['type'], 'files' => $deleted['files'], 'bytes' => $deleted['bytes']]
        );
        $this->flash('success', 'Media deleted successfully.');
        $this->redirect('/admin/media');
    }

    public function content(array $p): void
    {
        $this->requireAuth();
        $this->html($this->layout('Content', $this->contentContent()));
    }

    public function contentSave(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $admin = AdminModel::currentAdmin();

        $privacyTitle = trim((string)($_POST['privacy_title'] ?? 'Privacy policy'));
        $privacyBody = trim((string)($_POST['privacy_body'] ?? ''));
        $termsTitle = trim((string)($_POST['terms_title'] ?? 'Terms of service'));
        $termsBody = trim((string)($_POST['terms_body'] ?? ''));
        $rulesRaw = (string)($_POST['rules'] ?? '');
        $rules = preg_split('/\R+/', $rulesRaw) ?: [];

        AdminModel::saveInstanceContent('privacy', $privacyTitle, $privacyBody, 'text', $admin['id'] ?? '');
        AdminModel::saveInstanceContent('terms', $termsTitle, $termsBody, 'text', $admin['id'] ?? '');
        AdminModel::saveInstanceRules($rules, $admin['id'] ?? '');
        AdminModel::logAction(
            $admin['id'] ?? null,
            'instance.content.update',
            'instance',
            'content',
            'Updated legal pages and server rules.',
            ['privacy' => $privacyBody !== '', 'terms' => $termsBody !== '', 'rules' => count(array_filter(array_map('trim', $rules)))]
        );

        $this->flash('success', 'Instance content saved.');
        $this->redirect('/admin/content');
    }

    public function reports(array $p): void
    {
        $this->requireAuth();
        $page = max(1, (int)($_GET['page'] ?? 1));
        $status = (string)($_GET['status'] ?? 'all');
        $data = AdminModel::listReports($page, $status);
        $this->html($this->layout('Reports', $this->reportsContent($data, $status)));
    }

    public function reportCreate(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $admin = AdminModel::currentAdmin();

        $targetKind = trim((string)($_POST['target_kind'] ?? 'account'));
        $targetLabel = trim((string)($_POST['target_label'] ?? ''));
        $reason = trim((string)($_POST['reason'] ?? ''));
        $comment = trim((string)($_POST['comment'] ?? ''));

        if ($targetLabel === '' || $reason === '') {
            $this->flash('error', 'Target and reason are required.');
            $this->redirect('/admin/reports');
        }

        $id = AdminModel::createReport([
            'reporter_id' => $admin['id'] ?? '',
            'target_kind' => $targetKind,
            'target_label' => $targetLabel,
            'reason' => $reason,
            'comment' => $comment,
        ]);
        AdminModel::logAction(
            $admin['id'] ?? null,
            'report.create',
            'report',
            $id,
            'Created a moderation report.',
            ['target_kind' => $targetKind, 'target_label' => $targetLabel, 'reason' => $reason]
        );

        $this->flash('success', 'Report created.');
        $this->redirect('/admin/reports');
    }

    public function reportUpdate(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $admin = AdminModel::currentAdmin();
        $id = (string)($p['id'] ?? '');
        $report = AdminModel::reportById($id);
        if (!$report) {
            $this->flash('error', 'Report not found.');
            $this->redirect('/admin/reports');
        }

        $status = trim((string)($_POST['status'] ?? 'open'));
        $moderationAction = trim((string)($_POST['moderation_action'] ?? ''));
        $resolutionNote = trim((string)($_POST['resolution_note'] ?? ''));
        $update = [
            'status' => $status,
            'moderation_action' => $moderationAction,
            'resolution_note' => $resolutionNote,
            'handled_by' => $admin['id'] ?? '',
            'handled_at' => now_iso(),
        ];
        AdminModel::updateReport($id, $update);
        AdminModel::logAction(
            $admin['id'] ?? null,
            'report.update',
            'report',
            $id,
            'Updated a moderation report.',
            ['status' => $status, 'moderation_action' => $moderationAction]
        );

        $this->flash('success', 'Report updated.');
        $this->redirect('/admin/reports');
    }

    // ── Federation / domains ─────────────────────────────────

    public function federation(array $p): void
    {
        $this->requireAuth();
        $page    = max(1, (int)($_GET['page'] ?? 1));
        $q       = trim($_GET['q'] ?? '');
        $domains = AdminModel::listDomains($page, $q);
        $blocked = AdminModel::listBlockedDomains();
        $this->html($this->layout('Federation', $this->federationContent($domains, $blocked, $q)));
    }

    public function federationAction(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $action = $_POST['action'] ?? '';
        $domain = trim($_POST['domain'] ?? '');
        $admin  = AdminModel::currentAdmin();

        if (!$domain) { $this->redirect('/admin/federation'); }

        if ($action === 'block') {
            AdminModel::blockDomain($domain, true, $admin['id']);
            AdminModel::logAction($admin['id'] ?? null, 'federation.block', 'domain', strtolower($domain), 'Blocked a domain.', ['domain' => strtolower($domain)]);
            $this->flash('success', "Domain <strong>" . htmlspecialchars($domain) . "</strong> blocked.");
        } elseif ($action === 'unblock') {
            AdminModel::blockDomain($domain, false, $admin['id']);
            AdminModel::logAction($admin['id'] ?? null, 'federation.unblock', 'domain', strtolower($domain), 'Unblocked a domain.', ['domain' => strtolower($domain)]);
            $this->flash('success', "Domain <strong>" . htmlspecialchars($domain) . "</strong> unblocked.");
        }
        $this->redirect('/admin/federation');
    }

    public function federationRefetchActor(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $actorUrl = trim((string)($_POST['actor_url'] ?? ''));
        if ($actorUrl === '') {
            $this->flash('error', 'Actor URL is required.');
            $this->redirect('/admin/federation');
        }
        $result = AdminModel::refetchRemoteActor($actorUrl);
        if (!empty($result['ok'])) {
            $this->flash('success', 'Actor refreshed: <strong>' . htmlspecialchars($actorUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</strong>');
        } else {
            $this->flash('error', 'Could not refresh actor: <strong>' . htmlspecialchars($actorUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</strong> (' . htmlspecialchars((string)($result['error'] ?? 'unknown_error'), ENT_QUOTES | ENT_HTML5, 'UTF-8') . ')');
        }
        $this->redirect('/admin/federation');
    }

    public function settings(array $p): void
    {
        $this->requireAuth();
        $this->html($this->layout('Settings', $this->settingsContent()));
    }

    public function settingsSave(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();

        $siteName = trim((string)($_POST['site_name'] ?? ''));
        $baseUrl = rtrim(trim((string)($_POST['base_url'] ?? '')), '/');
        $adminEmail = trim((string)($_POST['admin_email'] ?? ''));
        $description = trim((string)($_POST['description'] ?? ''));
        $sourceUrl = rtrim(trim((string)($_POST['source_url'] ?? '')), '/');
        $atprotoDid = trim((string)($_POST['atproto_did'] ?? ''));
        $oauthTokenTtlDays = max(0, min(3650, (int)($_POST['oauth_token_ttl_days'] ?? 0)));
        $openReg = !empty($_POST['open_reg']);

        $scheme = (string)parse_url($baseUrl, PHP_URL_SCHEME);
        $domain = (string)parse_url($baseUrl, PHP_URL_HOST);
        $path = (string)parse_url($baseUrl, PHP_URL_PATH);

        if ($siteName === '' || $baseUrl === '' || $adminEmail === '') {
            $this->flash('error', 'Site name, base URL, and administrator email are required.');
            $this->redirect('/admin/settings');
        }
        if (!filter_var($baseUrl, FILTER_VALIDATE_URL) || !in_array($scheme, ['http', 'https'], true) || $domain === '') {
            $this->flash('error', 'Base URL must be a valid http:// or https:// URL.');
            $this->redirect('/admin/settings');
        }
        if ($path !== '' && $path !== '/') {
            $this->flash('error', 'Base URL must not include a path.');
            $this->redirect('/admin/settings');
        }
        if (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
            $this->flash('error', 'Invalid administrator email address.');
            $this->redirect('/admin/settings');
        }
        if ($sourceUrl !== '' && !filter_var($sourceUrl, FILTER_VALIDATE_URL)) {
            $this->flash('error', 'Source URL must be a valid URL.');
            $this->redirect('/admin/settings');
        }

        $current = $this->readGeneratedConfig();
        $current['installed'] = true;
        $current['domain'] = strtolower($domain);
        $current['name'] = $siteName;
        $current['description'] = $description !== '' ? $description : ($siteName . ' is an ActivityPub server.');
        $current['admin_email'] = strtolower($adminEmail);
        $current['base_url'] = $baseUrl;
        $current['db_path'] = $current['db_path'] ?? ROOT . '/storage/db/activitypub.sqlite';
        $current['media_dir'] = $current['media_dir'] ?? ROOT . '/storage/media';
        $current['max_upload_mb'] = $current['max_upload_mb'] ?? AP_MAX_UPLOAD_MB;
        $current['open_reg'] = $openReg;
        $current['post_chars'] = $current['post_chars'] ?? AP_POST_CHARS;
        $current['debug'] = $current['debug'] ?? AP_DEBUG;
        $current['version'] = $current['version'] ?? AP_VERSION;
        $current['software'] = $current['software'] ?? AP_SOFTWARE;
        $current['source_url'] = $sourceUrl !== '' ? $sourceUrl : $baseUrl;
        $current['atproto_did'] = $atprotoDid;
        $current['oauth_token_ttl_days'] = $oauthTokenTtlDays;

        $this->writeGeneratedConfig($current);
        $admin = AdminModel::currentAdmin();
        AdminModel::logAction(
            $admin['id'] ?? null,
            'settings.update',
            'instance',
            AP_DOMAIN,
            'Updated instance settings.',
            ['site_name' => $siteName, 'base_url' => $baseUrl, 'admin_email' => strtolower($adminEmail), 'open_reg' => $openReg, 'oauth_token_ttl_days' => $oauthTokenTtlDays]
        );
        $this->flash('success', 'Instance settings saved. Reload the app to see all changes reflected everywhere.');
        $this->redirect('/admin/settings');
    }

    // ── Inbox log ────────────────────────────────────────────

    public function inboxLog(array $p): void
    {
        $this->requireAuth();
        $page   = max(1, (int)($_GET['page'] ?? 1));
        $type   = $_GET['type'] ?? '';
        $errors = !empty($_GET['errors']);
        $data   = AdminModel::inboxLog($page, $type, $errors);
        $this->html($this->layout('Inbox Log', $this->inboxLogContent($data, $type, $errors)));
    }

    public function inboxLogDetail(array $p): void
    {
        $this->requireAuth();
        $row = AdminModel::inboxLogDetail($p['id']);
        if (!$row) { $this->flash('error', 'Entry not found.'); $this->redirect('/admin/inbox-log'); }
        $this->html($this->layout('Detail — Inbox Log', $this->inboxDetailContent($row)));
    }

    public function retryInboxLog(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $id = (string)($p['id'] ?? '');
        $result = AdminModel::retryInboxLogEntry($id);
        if (empty($result['ok'])) {
            $this->flash('error', 'Retry failed: ' . htmlspecialchars((string)($result['error'] ?? 'unknown_error'), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            $this->redirect('/admin/inbox-log/' . rawurlencode($id));
        }
        $msg = !empty($result['accepted'])
            ? 'Inbox entry reprocessed and accepted. A new inbox log entry was created.'
            : 'Inbox entry reprocessed and rejected again. A new inbox log entry was created.';
        $this->flash('success', $msg);
        $this->redirect('/admin/inbox-log/' . rawurlencode($id));
    }

    // ── Maintenance ───────────────────────────────────────────

    public function maintenance(array $p): void
    {
        $this->requireAuth();
        $disk = AdminModel::diskReport();
        $this->html($this->layout('Maintenance', $this->maintenanceContent($disk)));
    }

    public function maintenanceAction(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $action = $_POST['action'] ?? '';
        $admin = AdminModel::currentAdmin();
        @set_time_limit(0);

        try {
            $postResponse = null;
            $msg = match ($action) {
            'prune_inbox' => (function() {
                $days = max(1, (int)($_POST['days'] ?? 30));
                $n = AdminModel::pruneInboxLog($days);
                return "Deleted <strong>$n</strong> inbox log entries (>{$days} days).";
            })(),
            'prune_remote_posts' => (function() {
                $days = max(1, (int)($_POST['days'] ?? 30));
                $n = AdminModel::pruneRemotePosts($days);
                return "Deleted <strong>$n</strong> remote posts (>{$days} days, no active follows).";
            })(),
            'prune_followed_remote_posts' => (function() {
                $days = max(1, (int)($_POST['days'] ?? AdminModel::AGGRESSIVE_DEFAULTS['followed_remote_posts_days']));
                $n = AdminModel::pruneFollowedRemotePosts($days);
                return "Deleted <strong>$n</strong> followed remote posts (>{$days} days, protected local references kept).";
            })(),
            'prune_remote_actors' => (function() {
                $days = max(1, (int)($_POST['days'] ?? 60));
                $n = AdminModel::pruneRemoteActors($days);
                return "Removed <strong>$n</strong> unfollowed remote actors (>{$days} days).";
            })(),
            'prune_orphan_media' => (function() {
                $hours = max(1, (int)($_POST['hours'] ?? AdminModel::AGGRESSIVE_DEFAULTS['orphan_media_hours']));
                $r = AdminModel::pruneOrphanMedia($hours);
                $freed = AdminModel::formatBytes($r['bytes']);
                return "Deleted <strong>{$r['files']}</strong> orphaned media files. Freed <strong>$freed</strong>.";
            })(),
            'prune_notifications' => (function() {
                $days = max(1, (int)($_POST['days'] ?? 60));
                $n = AdminModel::pruneNotifications($days);
                return "Deleted <strong>$n</strong> notifications (>{$days} days).";
            })(),
            'prune_tokens' => (function() {
                $days = max(1, (int)($_POST['days'] ?? AdminModel::AGGRESSIVE_DEFAULTS['tokens_days']));
                $n = AdminModel::pruneOldTokens($days);
                return "Removed <strong>$n</strong> OAuth tokens older than {$days} days.";
            })(),
            'toggle_auto_maintenance' => (function() {
                $enable = (string)($_POST['enable'] ?? '1') === '1';
                AdminModel::setAutoMaintenanceEnabled($enable);
                return $enable
                    ? 'Automatic maintenance enabled.'
                    : 'Automatic maintenance disabled.';
            })(),
            'vacuum' => (function() use (&$postResponse) {
                $postResponse = static function (): void {
                    try { AdminModel::vacuumWithLock(); } catch (\Throwable $e) {
                        error_log('Manual vacuum failed: ' . $e->getMessage());
                    }
                };
                return 'VACUUM started in the background. The page may show the new database size a few seconds later.';
            })(),
            'prune_link_cards' => (function() {
                $days = max(1, (int)($_POST['days'] ?? 30));
                $n = AdminModel::pruneLinkCards($days);
                return "Deleted <strong>$n</strong> link cards (>{$days} days).";
            })(),
            'prune_runtime' => (function() {
                $days = max(1, (int)($_POST['days'] ?? AdminModel::AGGRESSIVE_DEFAULTS['runtime_days']));
                $r = AdminModel::pruneRuntimeArtifacts($days);
                $freed = AdminModel::formatBytes($r['bytes']);
                return "Deleted <strong>{$r['files']}</strong> old runtime files. Freed <strong>$freed</strong>.";
            })(),
            'prune_all' => (function() use (&$postResponse) {
                $r     = AdminModel::pruneAll();
                if (AdminModel::shouldVacuumAfterCleanup($r)) {
                    $postResponse = static function (): void {
                        try { AdminModel::vacuumWithLock(); } catch (\Throwable $e) {
                            error_log('Post-cleanup vacuum failed: ' . $e->getMessage());
                        }
                    };
                    $vacuumNote = ' Database compaction (VACUUM) started in the background.';
                } else {
                    $vacuumNote = ' Database compaction was not needed this round.';
                }
                return implode(' · ', array_filter([
                    $r['inbox']  ? "<strong>{$r['inbox']}</strong> inbox log entries"        : null,
                    $r['posts']  ? "<strong>{$r['posts']}</strong> unfollowed remote posts"  : null,
                    $r['followed_posts'] ? "<strong>{$r['followed_posts']}</strong> followed remote posts" : null,
                    $r['actors'] ? "<strong>{$r['actors']}</strong> remote actors"           : null,
                    $r['notifs'] ? "<strong>{$r['notifs']}</strong> notifications"           : null,
                    $r['media']['files'] ? "<strong>{$r['media']['files']}</strong> orphaned media files" : null,
                    $r['tokens'] ? "<strong>{$r['tokens']}</strong> tokens OAuth"            : null,
                    $r['cards']  ? "<strong>{$r['cards']}</strong> link cards"               : null,
                    $r['runtime']['files'] ? "<strong>{$r['runtime']['files']}</strong> runtime files" : null,
                    $r['delivery_log'] ? "<strong>{$r['delivery_log']}</strong> delivery history entries" : null,
                ])) . '.' . $vacuumNote;
            })(),
            'delete_remote_post' => (function() {
                $uri = trim($_POST['uri'] ?? '');
                if (!$uri) return 'Missing URI.';
                $ok = AdminModel::deleteRemotePostByUri($uri);
                return $ok
                    ? "Remote post deleted: <strong>" . htmlspecialchars($uri) . "</strong>"
                    : "Post not found (or it is local): <strong>" . htmlspecialchars($uri) . "</strong>";
            })(),
            default => 'Unknown action.',
            };
        } catch (\Throwable $e) {
            $this->flash('error', 'Maintenance error: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            $this->redirect('/admin/maintenance');
            return;
        }

        if ($postResponse) {
            defer_after_response($postResponse);
        }
        AdminModel::logAction($admin['id'] ?? null, 'maintenance.' . $action, 'maintenance', $action, 'Ran an admin maintenance action.', ['action' => $action]);
        $this->flash('success', $msg);
        $this->redirect('/admin/maintenance');
    }

    // ── Delivery queue ────────────────────────────────────────

    public function deliveryQueue(array $p): void
    {
        $this->requireAuth();
        $data = AdminModel::deliveryQueueOverview();
        $this->html($this->layout('Deliveries', $this->deliveryQueueContent(
            $data['rows'],
            $data['stats'],
            $data['errorBuckets'],
            $data['topDomains'],
            $data['recentAttempts'] ?? [],
            $data['recentBatches'] ?? [],
            $data['batchStats'] ?? [],
            $data['tuning'] ?? [],
            $data['profiles'] ?? [],
            $data['matchedProfile'] ?? 'custom'
        )));
    }

    public function deliveryQueueAction(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $action = $_POST['action'] ?? '';
        $admin = AdminModel::currentAdmin();

        $msg = match ($action) {
            'save_tuning' => (function () use ($admin) {
                $preset = trim((string)($_POST['preset'] ?? 'custom'));
                $saved = AdminModel::saveDeliveryQueueTuning($_POST, (string)($admin['id'] ?? ''), $preset);
                $matched = AdminModel::matchDeliveryQueueProfile($saved);
                $label = $matched !== 'custom'
                    ? (AdminModel::deliveryQueueProfiles()[$matched]['label'] ?? 'preset')
                    : 'custom settings';
                return 'Delivery queue tuning saved: <strong>' . htmlspecialchars($label, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</strong>.';
            })(),
            'retry_all' => (function () {
                $now = gmdate('Y-m-d\TH:i:s\Z');
                $n = (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts<=7")['c'] ?? 0);
                DB::run("UPDATE delivery_queue SET next_retry_at=?, processing_until='', last_error_bucket='', last_error_detail='' WHERE attempts<=7", [$now]);
                defer_after_response(static function (): void {
                    \App\ActivityPub\Delivery::nudgeQueue(true);
                });
                return "Scheduled <strong>$n</strong> deliveries for immediate retry.";
            })(),
            'clear_failed' => (function () {
                $n = (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue WHERE attempts>=8")['c'] ?? 0);
                DB::run("DELETE FROM delivery_queue WHERE attempts>=8");
                return "Removed <strong>$n</strong> deliveries in terminal failure.";
            })(),
            'clear_all' => (function () {
                $n = (int)(DB::one("SELECT COUNT(*) c FROM delivery_queue")['c'] ?? 0);
                DB::run("DELETE FROM delivery_queue");
                return "Queue cleared. Removed <strong>$n</strong> deliveries.";
            })(),
            default => 'Unknown action.',
        };

        AdminModel::logAction($admin['id'] ?? null, 'delivery.' . $action, 'delivery_queue', $action, 'Updated the delivery queue.', ['action' => $action]);
        $this->flash('success', $msg);
        $this->redirect('/admin/delivery-queue');
    }

    public function relays(array $p): void
    {
        $this->requireAuth();
        $rows = DB::all("SELECT * FROM relay_subscriptions ORDER BY created_at DESC");
        $this->html($this->layout('Relays', $this->relaysContent($rows)));
    }

    public function relayAction(array $p): void
    {
        $this->requireAuth();
        $this->requirePost();
        $action   = $_POST['action']    ?? '';
        $relayUrl = trim($_POST['relay_url'] ?? '');
        $admin    = AdminModel::currentAdmin();

        if ($action === 'subscribe') {
            if (!filter_var($relayUrl, FILTER_VALIDATE_URL) || !str_starts_with($relayUrl, 'https://')) {
                $this->flash('error', 'Invalid URL. It must start with https://');
                $this->redirect('/admin/relays');
            }
            if (DB::one("SELECT 1 FROM relay_subscriptions WHERE actor_url=?", [$relayUrl])) {
                $this->flash('error', 'Relay already subscribed.');
                $this->redirect('/admin/relays');
            }

            // Fetch relay actor to get inbox URL
            $actor = \App\Models\RemoteActorModel::fetch($relayUrl);
            $inbox = $actor['inbox_url'] ?? '';
            if (!$inbox) {
                $this->flash('error', 'Could not fetch the relay profile. Check the URL.');
                $this->redirect('/admin/relays');
            }

            // Get local admin user to send Follow as
            $sender = DB::one("SELECT * FROM users WHERE is_admin=1 ORDER BY created_at ASC LIMIT 1");
            if (!$sender) {
                $this->flash('error', 'No local admin user found.');
                $this->redirect('/admin/relays');
            }

            $dailyLimit = max(50, min(5000, (int)($_POST['daily_limit'] ?? 500)));
            $receivePosts = !empty($_POST['receive_posts']) ? 1 : 0;

            // Store subscription as pending
            DB::run(
                "INSERT INTO relay_subscriptions (id, actor_url, inbox_url, status, receive_posts, daily_limit, created_at)
                 VALUES (?,?,?,'pending',?,?,?)",
                [flake_id(), $relayUrl, $inbox, $receivePosts, $dailyLimit, now_iso()]
            );

            // Queue Follow activity to relay inbox; process immediately after the response
            $follow = \App\ActivityPub\Builder::follow($sender, $relayUrl);
            \App\ActivityPub\Delivery::enqueue($sender, $inbox, $follow);
            AdminModel::logAction($admin['id'] ?? null, 'relay.subscribe', 'relay', $relayUrl, 'Subscribed to a relay.', ['relay_url' => $relayUrl, 'daily_limit' => $dailyLimit, 'receive_posts' => $receivePosts]);
            $this->flash('success', 'Follow queued for the relay. Waiting for confirmation (Accept).');
        } elseif ($action === 'unsubscribe') {
            $row = DB::one("SELECT * FROM relay_subscriptions WHERE actor_url=?", [$relayUrl]);
            if ($row) {
                $sender = DB::one("SELECT * FROM users WHERE is_admin=1 ORDER BY created_at ASC LIMIT 1");
                if ($sender && $row['inbox_url']) {
                    $undo = \App\ActivityPub\Builder::undoFollow($sender, $relayUrl);
                    \App\ActivityPub\Delivery::enqueue($sender, $row['inbox_url'], $undo);
                }
                DB::run("DELETE FROM relay_subscriptions WHERE actor_url=?", [$relayUrl]);
                AdminModel::logAction($admin['id'] ?? null, 'relay.unsubscribe', 'relay', $relayUrl, 'Unsubscribed from a relay.', ['relay_url' => $relayUrl]);
                $this->flash('success', 'Relay removed and Undo Follow queued.');
            }
        } elseif ($action === 'toggle_receive') {
            $row = DB::one("SELECT * FROM relay_subscriptions WHERE actor_url=?", [$relayUrl]);
            if ($row) {
                $newValue = empty($row['receive_posts']) ? 1 : 0;
                DB::run("UPDATE relay_subscriptions SET receive_posts=? WHERE actor_url=?", [$newValue, $relayUrl]);
                AdminModel::logAction($admin['id'] ?? null, 'relay.toggle_receive', 'relay', $relayUrl, 'Changed relay receive mode.', ['relay_url' => $relayUrl, 'receive_posts' => $newValue]);
                $this->flash(
                    'success',
                    $newValue
                        ? 'Receiving posts from the relay enabled.'
                        : 'Receiving posts from the relay disabled. The relay is still used for outbound delivery.'
                );
            }
        }

        $this->redirect('/admin/relays');
    }

    // ── Infrastructure: response helpers ─────────────────────

    private function requireAuth(): void
    {
        AdminModel::startSession();
        if (!AdminModel::isLoggedIn()) {
            $this->redirect('/admin/login');
        }
        // Ensure a per-session CSRF token exists for admin action forms
        if (empty($_SESSION['admin_csrf'])) {
            $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
        }
    }

    private function requirePost(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->redirect('/admin');
        }
        // Verify CSRF token on every state-changing POST
        $token = $_POST['_csrf'] ?? '';
        if (!hash_equals($_SESSION['admin_csrf'] ?? '', $token)) {
            http_response_code(403);
            $this->html('<h1>403 — Invalid request (incorrect CSRF token).</h1>');
        }
    }

    private function fmtDate(string $iso): string
    {
        $ts = strtotime($iso);
        return $ts === false ? '—' : date('Y-m-d', $ts);
    }

    private function fmtDateTime(string $iso): string
    {
        $ts = strtotime($iso);
        return $ts === false ? '—' : date('Y-m-d H:i:s', $ts);
    }

    private function fmtDateTimeShort(string $iso): string
    {
        $ts = strtotime($iso);
        return $ts === false ? '—' : date('Y-m-d H:i', $ts);
    }

    private function redirect(string $url): never
    {
        header('Location: ' . $url); exit;
    }

    private function flash(string $type, string $msg): void
    {
        AdminModel::startSession();
        $_SESSION['flash'] = ['type' => $type, 'msg' => $msg];
    }

    private function getFlash(): ?array
    {
        AdminModel::startSession();
        $f = $_SESSION['flash'] ?? null;
        unset($_SESSION['flash']);
        return $f;
    }

    private function html(string $content): never
    {
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('X-Content-Type-Options: nosniff');
        header('X-Robots-Tag: noindex, nofollow');
        header("Content-Security-Policy: base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self';");
        echo $content;
        exit;
    }

    // ╔══════════════════════════════════════════════════════════╗
    // ║  TEMPLATES                                               ║
    // ╚══════════════════════════════════════════════════════════╝

    private function layout(string $title, string $body): string
    {
        $flash      = $this->getFlash();
        $admin      = AdminModel::currentAdmin();
        $e          = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $csrfToken  = $e($_SESSION['admin_csrf'] ?? '');
        $flashHtml  = '';
        if ($flash) {
            $cls = $flash['type'] === 'error' ? 'flash-error' : 'flash-ok';
            $flashHtml = "<div class='flash $cls'>{$flash['msg']}</div>";
        }
        $nav = [
            '/admin'                  => 'Dashboard',
            '/admin/users'            => 'Users',
            '/admin/reports'          => 'Reports',
            '/admin/media'            => 'Media',
            '/admin/content'          => 'Content',
            '/admin/settings'         => 'Settings',
            '/admin/federation'       => 'Federation',
            '/admin/relays'           => 'Relays',
            '/admin/inbox-log'        => 'Inbox Log',
            '/admin/delivery-queue'   => 'Deliveries',
            '/admin/action-log'       => 'Action Log',
            '/admin/maintenance'      => 'Maintenance',
        ];
        $navHtml = '';
        $current = strtok($_SERVER['REQUEST_URI'] ?? '/admin', '?');
        foreach ($nav as $href => $label) {
            $active = ($current === $href) ? ' active' : '';
            $navHtml .= "<a href='$href' class='nav-item$active'>$label</a>";
        }
        $adminName = $e($admin['username'] ?? '');
        $domain    = $e(AP_DOMAIN);
        $ver       = $e(AP_VERSION);

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{$e($title)} — Admin · {$domain}</title>
<link rel="icon" href="{$e(\site_favicon_url())}">
<style>
:root {
  --bg:      #fff;
  --bg2:     #ffffff;
  --bg3:     #F3F3F8;
  --bg4:     #E8E8EE;
  --border:  #E5E7EB;
  --border2: #D1D5DB;
  --blue:    #0085FF;
  --blue2:   #0070E0;
  --blue-bg: #E0EDFF;
  --green:   #20BC07;
  --green-bg:#E0F8DC;
  --red:     #EC4040;
  --red-bg:  #FDE8E8;
  --amber:   #FFC404;
  --amber2:  #E0AC00;
  --amber-bg:#FFF8E0;
  --purple:  #7856ff;
  --text:    #0F1419;
  --text2:   #66788A;
  --text3:   #8D99A5;
}
@media(prefers-color-scheme:dark) {
  :root {
    --bg:      #0A0E14;
    --bg2:     #161823;
    --bg3:     #1E2030;
    --bg4:     #272A36;
    --border:  #2E3039;
    --border2: #3D4049;
    --text:    #F1F3F5;
    --text2:   #7B8794;
    --text3:   #545864;
    --blue-bg: #0C1B3A;
    --green-bg:#0C2A0A;
    --red-bg:  #2A0C0C;
    --amber-bg:#2A2200;
  }
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 14px; }
body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, sans-serif; min-height: 100vh; display: flex; flex-direction: column; }

/* Top bar */
.topbar {
  background: color-mix(in srgb, var(--bg2) 85%, transparent);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
  padding: .6rem 1.5rem;
  display: flex; align-items: center; gap: 1rem;
  position: sticky; top: 0; z-index: 100;
}
.topbar-brand {
  font-size: .95rem; font-weight: 800; color: var(--text);
  display: flex; align-items: center; gap: .5rem; letter-spacing: -.01em;
}
.topbar-brand span { color: var(--text2); font-weight: 500; font-size: .82rem; }
.topbar-domain { color: var(--text2); font-size: .78rem; }
.topbar-right { margin-left: auto; display: flex; align-items: center; gap: 1rem; }
.topbar-admin { color: var(--blue); font-size: .78rem; font-weight: 600; }
.topbar-admin::before { content: '● '; color: var(--green); }
.btn-logout { background: none; border: 1px solid var(--border); color: var(--text2); padding: .3rem .8rem; border-radius: 9999px; cursor: pointer; font-size: .78rem; text-decoration: none; transition: all .15s; }
.btn-logout:hover { border-color: var(--red); color: var(--red); }

/* Sidebar */
.shell { display: flex; flex: 1; }
.sidebar {
  width: 210px; min-width: 210px;
  background: var(--bg2);
  border-right: 1px solid var(--border);
  padding: 1.5rem 0;
  position: sticky; top: 41px;
  height: calc(100vh - 41px);
  overflow-y: auto;
}
.nav-section { padding: .4rem 1rem .2rem; color: var(--text3); font-size: .65rem; letter-spacing: .1em; text-transform: uppercase; font-weight: 600; }
.nav-item {
  display: block; padding: .55rem 1.2rem;
  color: var(--text2); text-decoration: none; font-size: .85rem;
  border-left: 2px solid transparent;
  transition: all .1s; font-weight: 500;
}
.nav-item:hover { color: var(--text); background: var(--bg3); text-decoration: none; }
.nav-item.active { color: var(--blue); border-left-color: var(--blue); background: var(--blue-bg); }

/* Main */
.main { flex: 1; padding: 2rem 2.5rem; max-width: 1200px; }
.page-title { font-size: 1.3rem; font-weight: 800; margin-bottom: 1.5rem; color: var(--text); display: flex; align-items: baseline; gap: .8rem; letter-spacing: -.02em; }
.page-title small { font-size: .7rem; color: var(--text3); font-weight: 400; }

/* Flash */
.flash { padding: .7rem 1rem; margin-bottom: 1.2rem; border-radius: 8px; font-size: .85rem; border-left: 3px solid; }
.flash-ok    { background: var(--green-bg); border-color: var(--green); color: var(--green); }
.flash-error { background: var(--red-bg);   border-color: var(--red);   color: var(--red); }

/* Cards */
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: .8rem; margin-bottom: 2rem; }
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.2rem; }
.card-label { font-size: .65rem; letter-spacing: .06em; text-transform: uppercase; color: var(--text3); margin-bottom: .3rem; font-weight: 600; }
.card-value { font-size: 1.6rem; font-weight: 800; color: var(--text); line-height: 1; }
.card-sub { font-size: .7rem; color: var(--text2); margin-top: .2rem; }
.card.amber .card-value { color: var(--amber); }
.card.green .card-value { color: var(--green); }
.card.blue  .card-value { color: var(--blue); }
.card.red   .card-value { color: var(--red); }

/* Section */
.section { margin-bottom: 2rem; }
.section-title { font-size: .7rem; letter-spacing: .08em; text-transform: uppercase; color: var(--text3); border-bottom: 1px solid var(--border); padding-bottom: .5rem; margin-bottom: 1rem; font-weight: 600; }

/* Table */
.tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
thead th { background: var(--bg3); color: var(--text2); padding: .65rem .9rem; text-align: left; font-weight: 600; border-bottom: 1px solid var(--border); white-space: nowrap; }
tbody tr { border-bottom: 1px solid var(--border); transition: background .1s; }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--bg3); }
td { padding: .65rem .9rem; color: var(--text); vertical-align: middle; }
.td-mono { font-family: ui-monospace, "Cascadia Code", "SF Mono", monospace; font-size: .8rem; }
.td-dim { color: var(--text2); }

/* Badges */
.badge { display: inline-block; padding: .18rem .5rem; border-radius: 9999px; font-size: .68rem; font-weight: 700; letter-spacing: .02em; }
.badge-green  { background: var(--green-bg); color: var(--green); }
.badge-red    { background: var(--red-bg);   color: var(--red); }
.badge-amber  { background: var(--amber-bg); color: var(--amber2); }
.badge-blue   { background: var(--blue-bg);  color: var(--blue); }
.badge-purple { background: #f0ecff;          color: var(--purple); }
.badge-dim    { background: var(--bg3);       color: var(--text2); }

/* Buttons */
.btn { display: inline-flex; align-items: center; gap: .35rem; padding: .42rem .9rem; border-radius: 9999px; cursor: pointer; font-size: .82rem; font-weight: 700; border: 1.5px solid; transition: all .15s; text-decoration: none; white-space: nowrap; font-family: inherit; }
.btn-primary { background: var(--blue); border-color: var(--blue); color: #fff; }
.btn-primary:hover { background: var(--blue2); border-color: var(--blue2); color: #fff; text-decoration: none; }
.btn-danger  { background: transparent; border-color: var(--red); color: var(--red); }
.btn-danger:hover  { background: var(--red-bg); text-decoration: none; }
.btn-ghost   { background: transparent; border-color: var(--border); color: var(--text2); }
.btn-ghost:hover   { border-color: var(--border2); color: var(--text); text-decoration: none; }
.btn-green   { background: transparent; border-color: var(--green); color: var(--green); }
.btn-green:hover   { background: var(--green-bg); text-decoration: none; }
.btn-sm { padding: .22rem .6rem; font-size: .74rem; }

/* Forms */
.form-row { display: flex; gap: .8rem; align-items: flex-end; flex-wrap: wrap; margin-bottom: 1rem; }
.form-group { display: flex; flex-direction: column; gap: .3rem; }
.form-group label { font-size: .7rem; color: var(--text2); letter-spacing: .04em; text-transform: uppercase; font-weight: 600; }
input[type=text], input[type=password], input[type=number], select {
  background: var(--bg2); border: 1px solid var(--border); color: var(--text);
  padding: .5rem .85rem; border-radius: 8px; font-size: .85rem;
  outline: none; transition: border .15s, box-shadow .15s; font-family: inherit;
}
input[type=email], input[type=url], textarea {
  background: var(--bg2); border: 1px solid var(--border); color: var(--text);
  padding: .5rem .85rem; border-radius: 8px; font-size: .85rem;
  outline: none; transition: border .15s, box-shadow .15s; font-family: inherit;
}
input:focus, select:focus { border-color: var(--blue); box-shadow: 0 0 0 3px var(--blue-bg); }
textarea:focus { border-color: var(--blue); box-shadow: 0 0 0 3px var(--blue-bg); }
input[type=number] { width: 80px; }

/* Chart bar */
.chart { display: flex; align-items: flex-end; gap: 3px; height: 60px; }
.bar-wrap { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 2px; height: 100%; justify-content: flex-end; }
.bar { width: 100%; background: var(--blue); border-radius: 3px 3px 0 0; min-height: 2px; transition: height .3s; opacity: .6; }
.bar:hover { opacity: 1; }
.bar-label { font-size: .55rem; color: var(--text3); white-space: nowrap; }

/* Maintenance panels */
.maint-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem; }
.maint-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 1.2rem 1.4rem; }
.maint-card h3 { font-size: .9rem; font-weight: 700; margin-bottom: .3rem; color: var(--text); }
.maint-card p { font-size: .8rem; color: var(--text2); margin-bottom: .9rem; line-height: 1.5; }
.maint-form { display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; }

/* Disk bar */
.disk-bar-wrap { background: var(--bg3); border-radius: 9999px; height: 6px; overflow: hidden; margin: .5rem 0; }
.disk-bar-fill { height: 100%; background: var(--blue); border-radius: 9999px; transition: width .5s; }
.disk-bar-fill.red { background: var(--red); }
.disk-bar-fill.green { background: var(--green); }

/* Pagination */
.pagination { display: flex; gap: .4rem; margin-top: 1rem; align-items: center; }
.page-btn { padding: .3rem .7rem; border: 1px solid var(--border); border-radius: 9999px; color: var(--text2); text-decoration: none; font-size: .78rem; transition: all .15s; }
.page-btn:hover { border-color: var(--blue); color: var(--blue); text-decoration: none; }
.page-btn.current { background: var(--blue); color: #fff; border-color: var(--blue); }
.page-info { font-size: .72rem; color: var(--text3); margin-left: .5rem; }

/* Login page */
.login-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg); }
.login-box { width: 360px; }
.login-brand { text-align: center; margin-bottom: 2rem; }
.login-brand h1 { font-size: 1.4rem; font-weight: 800; color: var(--text); letter-spacing: -.02em; }
.login-brand h1 span { color: var(--blue); }
.login-brand p { font-size: .78rem; color: var(--text3); margin-top: .35rem; }
.login-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 16px; padding: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,.06); }
.login-card h2 { font-size: .78rem; font-weight: 700; margin-bottom: 1.4rem; color: var(--text3); letter-spacing: .06em; text-transform: uppercase; }
.login-field { margin-bottom: 1rem; }
.login-field label { display: block; font-size: .72rem; color: var(--text2); margin-bottom: .35rem; letter-spacing: .04em; text-transform: uppercase; font-weight: 600; }
.login-field input { width: 100%; }
.login-submit { width: 100%; margin-top: 1.4rem; padding: .72rem; font-size: .9rem; font-weight: 700; background: var(--blue); border: none; border-radius: 9999px; color: #fff; cursor: pointer; transition: background .15s; font-family: inherit; }
.login-submit:hover { background: var(--blue2); }

/* Code block */
pre.code { background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-size: .78rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; color: var(--text2); line-height: 1.6; font-family: ui-monospace, "Cascadia Code", "SF Mono", monospace; }

/* Responsive */
.menu-btn {
  display: none; background: none; border: none; cursor: pointer;
  color: var(--text2); padding: .3rem; border-radius: 6px;
  transition: color .15s, background .15s;
}
.menu-btn:hover { color: var(--text); background: var(--bg3); }
.menu-btn svg { display: block; }

.drawer-overlay {
  display: none; position: fixed; inset: 0; z-index: 199;
  background: rgba(0,0,0,.45);
}
.drawer-overlay.open { display: block; }

@media (max-width: 768px) {
  .menu-btn { display: flex; align-items: center; }
  .topbar-domain { display: none; }

  .sidebar {
    position: fixed; top: 0; left: -230px; height: 100vh;
    z-index: 200; width: 220px; min-width: 220px;
    transition: left .22s ease; box-shadow: 4px 0 16px rgba(0,0,0,.15);
    padding-top: 3.5rem;
  }
  .sidebar.open { left: 0; }

  .main { padding: 1rem; }

  /* Tables: make rows stack or allow horizontal scroll */
  .tbl-wrap { border-radius: 8px; }
  td, th { padding: .5rem .65rem; font-size: .8rem; }

  /* Cards grid: 2 columns on mobile */
  .cards { grid-template-columns: repeat(2, 1fr); }

  /* Maint grid: single column */
  .maint-grid { grid-template-columns: 1fr; }

  /* Form rows: stack */
  .form-row { flex-direction: column; align-items: stretch; }
  .form-row .btn { width: 100%; justify-content: center; }

  /* Page title smaller */
  .page-title { font-size: 1.1rem; }
}
</style>
</head>
<body>
<div class="topbar">
  <button class="menu-btn" id="menu-btn" aria-label="Menu">
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
      <line x1="2" y1="5"  x2="18" y2="5"/>
      <line x1="2" y1="10" x2="18" y2="10"/>
      <line x1="2" y1="15" x2="18" y2="15"/>
    </svg>
  </button>
  <div class="topbar-brand"><span style="font-size:1.05rem;color:var(--blue);line-height:1">⋰⋱</span> Admin<span>Starling</span></div>
  <div class="topbar-domain">{$domain}</div>
  <div class="topbar-right">
    <span class="topbar-admin">{$adminName}</span>
    <form method="POST" action="/admin/logout" style="margin:0">
      <input type="hidden" name="_csrf" value="{$csrfToken}">
      <button type="submit" class="btn-logout">Sign out</button>
    </form>
  </div>
</div>
<div class="drawer-overlay" id="drawer-overlay"></div>
<div class="shell">
  <nav class="sidebar" id="sidebar">
    <div class="nav-section">Management</div>
    {$navHtml}
    <div class="nav-section" style="margin-top:1rem">System</div>
    <a href="/web" class="nav-item">← Web client</a>
    <a href="/" class="nav-item">Public site</a>
    <div style="padding:1rem 1.2rem;font-size:.65rem;color:var(--text3);margin-top:auto">v{$ver}</div>
  </nav>
  <main class="main">
    <div class="page-title">{$e($title)} <small>//admin</small></div>
    {$flashHtml}
    {$body}
  </main>
</div>
<script>
// Auto-inject CSRF token into every POST form that doesn't already have one
(function(){
  var tok = '{$csrfToken}';
  document.querySelectorAll('form[method="POST"],form[method="post"]').forEach(function(f){
    if (!f.querySelector('input[name="_csrf"]')) {
      var h = document.createElement('input');
      h.type = 'hidden'; h.name = '_csrf'; h.value = tok;
      f.appendChild(h);
    }
  });
})();

// Mobile sidebar drawer
(function(){
  var btn     = document.getElementById('menu-btn');
  var sidebar = document.getElementById('sidebar');
  var overlay = document.getElementById('drawer-overlay');
  if (!btn || !sidebar || !overlay) return;

  function open() {
    sidebar.classList.add('open');
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
  function close() {
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
    document.body.style.overflow = '';
  }

  btn.addEventListener('click', function() {
    sidebar.classList.contains('open') ? close() : open();
  });
  overlay.addEventListener('click', close);

  // Close when a nav link is tapped (navigation will follow)
  sidebar.querySelectorAll('.nav-item').forEach(function(a) {
    a.addEventListener('click', close);
  });
})();
</script>
</body></html>
HTML;
    }

    // ── Dashboard content ─────────────────────────────────────

    private function dashboardContent(array $s): string
    {
        $e  = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $fb = fn($b) => AdminModel::formatBytes((int)$b);

        // Chart bars
        $max = max(1, max(array_column($s['chart'], 'count')));
        $bars = '';
        foreach ($s['chart'] as $pt) {
            $h   = round(($pt['count'] / $max) * 100);
            $bars .= "<div class='bar-wrap'><div class='bar' style='height:{$h}%' title='{$pt['day']}: {$pt['count']}'></div><div class='bar-label'>{$pt['day']}</div></div>";
        }

        // Top domains
        $domRows = '';
        foreach ($s['topDomains'] as $d) {
            $domRows .= "<tr><td class='td-mono'>{$e($d['domain'])}</td><td class='td-dim'>{$e($d['c'])} actors</td></tr>";
        }

        // Disk
        $dbPct    = $s['totalSpace'] > 0 ? min(100, round((($s['totalSpace'] - $s['freeSpace']) / $s['totalSpace']) * 100)) : 0;
        $diskCls  = $dbPct > 85 ? 'red' : ($dbPct > 65 ? '' : 'green');

        return <<<HTML
<div class="cards">
  <div class="card green"><div class="card-label">Users</div><div class="card-value">{$e($s['users'])}</div><div class="card-sub">+{$e($s['newUsers24h'])} today</div></div>
  <div class="card amber"><div class="card-label">Local posts</div><div class="card-value">{$e($s['localPosts'])}</div><div class="card-sub">+{$e($s['newPosts24h'])} today</div></div>
  <div class="card blue"><div class="card-label">Remote posts</div><div class="card-value">{$e($s['remotePosts'])}</div><div class="card-sub">cached</div></div>
  <div class="card"><div class="card-label">Follows</div><div class="card-value">{$e($s['follows'])}</div><div class="card-sub">{$e($s['pending'])} pending</div></div>
  <div class="card blue"><div class="card-label">Instances</div><div class="card-value">{$e($s['domains'])}</div><div class="card-sub">{$e($s['remoteActors'])} actors</div></div>
  <div class="card"><div class="card-label">Federation queue</div><div class="card-value">{$e($s['queueTotal'])}</div><div class="card-sub">{$e($s['queueDue'])} due, {$e($s['queueFailed'])} in the latest attempt</div></div>
  <div class="card"><div class="card-label">Inbox log</div><div class="card-value">{$e($s['inboxLog'])}</div><div class="card-sub">+{$e($s['inboxItems24h'])} today</div></div>
  <div class="card"><div class="card-label">Database</div><div class="card-value">{$fb($s['dbSize'])}</div><div class="card-sub">SQLite</div></div>
  <div class="card"><div class="card-label">Media</div><div class="card-value">{$fb($s['mediaSize'])}</div><div class="card-sub">{$e($s['mediaFiles'])} files</div></div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem">
  <div class="section">
    <div class="section-title">Local posts — last 14 days</div>
    <div class="chart">{$bars}</div>
  </div>
  <div class="section">
    <div class="section-title">Top federated instances</div>
    <div class="tbl-wrap">
      <table><thead><tr><th>Domain</th><th>Actors</th></tr></thead>
      <tbody>{$domRows}</tbody></table>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Host filesystem</div>
  <div style="max-width:500px">
    <div style="display:flex;justify-content:space-between;font-size:.75rem;color:var(--text2);margin-bottom:.3rem">
      <span>Host disk used</span><span>{$fb($s['totalSpace'] - $s['freeSpace'])} / {$fb($s['totalSpace'])}</span>
    </div>
    <div class="disk-bar-wrap"><div class="disk-bar-fill {$diskCls}" style="width:{$dbPct}%"></div></div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:.5rem;margin-top:.8rem;font-size:.75rem">
      <div style="color:var(--text2)">Database<br><span style="color:var(--text)">{$fb($s['dbSize'])}</span></div>
      <div style="color:var(--text2)">Media<br><span style="color:var(--text)">{$fb($s['mediaSize'])}</span></div>
      <div style="color:var(--text2)">Inbox log (raw)<br><span style="color:var(--text)">{$fb($s['inboxLogSize'])}</span></div>
    </div>
    <div style="margin-top:.8rem;font-size:.75rem;color:var(--text2)">
      Starling storage footprint<br><strong style="color:var(--text)">{$fb($s['starlingStorageFootprint'])}</strong>
      <div style="margin-top:.25rem;color:var(--text3)">Database + media + runtime files. Raw inbox payload is shown separately as an estimate, not added again here.</div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Quick actions</div>
  <div style="display:flex;gap:.6rem;flex-wrap:wrap">
    <a href="/admin/maintenance" class="btn btn-ghost">Maintenance &amp; cleanup</a>
    <a href="/admin/inbox-log?errors=1" class="btn btn-ghost">View inbox errors</a>
    <a href="/admin/federation" class="btn btn-ghost">Manage federation</a>
  </div>
</div>
HTML;
    }

    // ── Users content ─────────────────────────────────────────

    private function usersContent(array $data, string $q, string $filter): string
    {
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $rows = '';
        foreach ($data['rows'] as $u) {
            $isAdmin = !empty($u['is_admin']);
            $isBot = !empty($u['is_bot']);
            $isLocked = !empty($u['is_locked']);
            $isSuspended = !empty($u['is_suspended']);
            $adminBadge = $u['is_admin']     ? "<span class='badge badge-amber'>admin</span> " : '';
            $botBadge   = $u['is_bot']       ? "<span class='badge badge-dim'>bot</span> "    : '';
            $lockBadge  = $isLocked          ? "<span class='badge badge-blue'>locked</span> " : '';
            $susp       = $isSuspended;
            $suspBadge  = $susp             ? "<span class='badge badge-red'>suspended</span>" : "<span class='badge badge-green'>active</span>";
            $suspBtn    = $susp
                ? "<form method='POST' action='/admin/users/{$e($u['id'])}/unsuspend' style='display:inline'><button class='btn btn-sm btn-green'>Reactivate</button></form>"
                : "<form method='POST' action='/admin/users/{$e($u['id'])}/suspend' style='display:inline'><button class='btn btn-sm btn-danger'>Suspend</button></form>";
            $adminBtn   = $isAdmin
                ? "<form method='POST' action='/admin/users/{$e($u['id'])}/toggle_admin' style='display:inline'><button class='btn btn-sm btn-ghost'>- Admin</button></form>"
                : "<form method='POST' action='/admin/users/{$e($u['id'])}/toggle_admin' style='display:inline'><button class='btn btn-sm btn-ghost'>+ Admin</button></form>";
            $editBtn    = "<button type='button' class='btn btn-sm btn-ghost' onclick=\"toggleUserEdit('user-edit-{$e($u['id'])}', this)\">Edit</button>";
            $delBtn     = "<form method='POST' action='/admin/users/{$e($u['id'])}/delete' style='display:inline' onsubmit='return confirm(\"Delete @{$e($u['username'])}? This action cannot be undone.\")'><button class='btn btn-sm btn-danger'>Delete</button></form>";
            $checkedAdmin = $isAdmin ? ' checked' : '';
            $checkedBot = $isBot ? ' checked' : '';
            $checkedLocked = $isLocked ? ' checked' : '';
            $rows .= "<tr>
              <td class='td-mono'>@{$e($u['username'])}<br><span class='td-dim' style='font-size:.7rem'>{$e($u['email'])}</span></td>
              <td>{$adminBadge}{$botBadge}{$lockBadge}{$suspBadge}</td>
              <td class='td-dim'>{$e($u['follower_count'])} followers / {$e($u['following_count'])} following</td>
              <td class='td-dim'>{$e($u['status_count'])} posts</td>
              <td class='td-dim' style='font-size:.7rem'>{$e($this->fmtDate($u['created_at'] ?? ''))}</td>
              <td style='white-space:nowrap'>$editBtn $suspBtn $adminBtn $delBtn</td>
            </tr>
            <tr id='user-edit-{$e($u['id'])}' style='display:none'>
              <td colspan='6' style='padding:0'>
                <form method='POST' action='/admin/users/{$e($u['id'])}/update' class='form-row' style='padding:1rem 1rem 1.2rem;border-top:1px solid var(--border);background:var(--bg3)'>
                  <div class='form-group'>
                    <label>Username</label>
                    <input type='text' value='{$e($u['username'])}' disabled>
                  </div>
                  <div class='form-group'>
                    <label>Email</label>
                    <input type='email' name='email' value='{$e($u['email'])}' required>
                  </div>
                  <div class='form-group'>
                    <label>Display name</label>
                    <input type='text' name='display_name' value='{$e($u['display_name'])}'>
                  </div>
                  <div class='form-group'>
                    <label>New password</label>
                    <input type='password' name='password' placeholder='Leave blank to keep current password'>
                  </div>
                  <div class='form-group' style='min-width:120px'>
                    <label>&nbsp;</label>
                    <label style='display:flex;align-items:center;gap:.45rem;cursor:pointer;text-transform:none;letter-spacing:0'>
                      <input type='checkbox' name='is_admin' value='1'{$checkedAdmin}> Administrator
                    </label>
                  </div>
                  <div class='form-group' style='min-width:100px'>
                    <label>&nbsp;</label>
                    <label style='display:flex;align-items:center;gap:.45rem;cursor:pointer;text-transform:none;letter-spacing:0'>
                      <input type='checkbox' name='is_bot' value='1'{$checkedBot}> Bot
                    </label>
                  </div>
                  <div class='form-group' style='min-width:110px'>
                    <label>&nbsp;</label>
                    <label style='display:flex;align-items:center;gap:.45rem;cursor:pointer;text-transform:none;letter-spacing:0'>
                      <input type='checkbox' name='is_locked' value='1'{$checkedLocked}> Locked
                    </label>
                  </div>
                  <div class='form-group'>
                    <label>&nbsp;</label>
                    <button class='btn btn-primary' type='submit'>Save changes</button>
                  </div>
                </form>
              </td>
            </tr>";
        }

        $filterOpts = ['all'=>'All','active'=>'Active','suspended'=>'Suspended','admin'=>'Admins'];
        $filterHtml = '';
        foreach ($filterOpts as $val => $label) {
            $sel = $filter === $val ? ' selected' : '';
            $filterHtml .= "<option value='$val'$sel>$label</option>";
        }

        $pager = $this->paginator($data['page'], $data['pages'], "/admin/users?q=" . urlencode($q) . "&filter=$filter");

        return <<<HTML
<div class="section">
  <div class="section-title">Create user</div>
  <form method="POST" action="/admin/users/create" class="form-row">
    <div class="form-group">
      <label>Username</label>
      <input type="text" name="username" placeholder="username" maxlength="30" required>
    </div>
    <div class="form-group">
      <label>Email</label>
      <input type="email" name="email" placeholder="user@example.com" required>
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" name="password" placeholder="Minimum 8 characters" minlength="8" required>
    </div>
    <div class="form-group">
      <label>Display name</label>
      <input type="text" name="display_name" placeholder="Optional">
    </div>
    <div class="form-group" style="min-width:140px">
      <label>&nbsp;</label>
      <label style="display:flex;align-items:center;gap:.45rem;cursor:pointer;text-transform:none;letter-spacing:0">
        <input type="checkbox" name="is_admin" value="1"> Administrator
      </label>
    </div>
    <div class="form-group" style="min-width:140px">
      <label>&nbsp;</label>
      <label style="display:flex;align-items:center;gap:.45rem;cursor:pointer;text-transform:none;letter-spacing:0">
        <input type="checkbox" name="is_bot" value="1"> Bot
      </label>
    </div>
    <div class="form-group">
      <label>&nbsp;</label>
      <button class="btn btn-primary" type="submit">Create user</button>
    </div>
  </form>
</div>

<div class="form-row">
  <form method="GET" action="/admin/users" style="display:flex;gap:.6rem;flex-wrap:wrap">
    <div class="form-group">
      <label>Search</label>
      <input type="text" name="q" value="{$e($q)}" placeholder="username, email..." style="width:200px">
    </div>
    <div class="form-group">
      <label>Filter</label>
      <select name="filter">{$filterHtml}</select>
    </div>
    <div class="form-group"><label>&nbsp;</label><button class="btn btn-primary" type="submit">Filter</button></div>
  </form>
</div>
<div style="font-size:.75rem;color:var(--text3);margin-bottom:.8rem">{$e($data['total'])} users</div>
<div class="tbl-wrap">
  <table>
    <thead><tr><th>User</th><th>Status</th><th>Followers</th><th>Posts</th><th>Created</th><th>Actions</th></tr></thead>
    <tbody>{$rows}</tbody>
  </table>
</div>
{$pager}
<script>
function toggleUserEdit(id, btn) {
  var row = document.getElementById(id);
  if (!row) return;
  var open = row.style.display !== 'none';
  row.style.display = open ? 'none' : '';
  if (btn) btn.textContent = open ? 'Edit' : 'Close';
}
</script>
HTML;
    }

    private function actionLogContent(array $data): string
    {
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $rows = '';
        foreach ($data['rows'] as $row) {
            $target = trim((string)($row['target_type'] ?? '')) !== ''
                ? $e(($row['target_type'] ?? '') . ':' . ($row['target_id'] ?? ''))
                : '—';
            $rows .= "<tr>
              <td class='td-dim' style='font-size:.75rem'>{$e($this->fmtDateTime($row['created_at'] ?? ''))}</td>
              <td class='td-mono'>{$e($row['admin_username'] ?? 'system')}</td>
              <td><span class='badge badge-blue'>{$e($row['action'])}</span></td>
              <td class='td-mono td-dim'>{$target}</td>
              <td>{$e($row['summary'] ?? '')}</td>
            </tr>";
        }
        if ($rows === '') {
            $rows = "<tr><td colspan='5' style='text-align:center;color:var(--text3);padding:1.5rem'>No admin actions logged yet.</td></tr>";
        }
        $pager = $this->paginator($data['page'], $data['pages'], '/admin/action-log');

        return <<<HTML
<div style="font-size:.75rem;color:var(--text3);margin-bottom:.8rem">{$e($data['total'])} actions</div>
<div class="tbl-wrap">
  <table>
    <thead><tr><th>When</th><th>Admin</th><th>Action</th><th>Target</th><th>Summary</th></tr></thead>
    <tbody>{$rows}</tbody>
  </table>
</div>
{$pager}
HTML;
    }

    private function mediaContent(array $data, string $q, string $type, bool $orphans): string
    {
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $rows = '';
        foreach ($data['rows'] as $row) {
            $attached = (string)($row['attached_status_id'] ?? '') !== ''
                ? "<span class='badge badge-green'>attached</span>"
                : "<span class='badge badge-amber'>orphan</span>";
            $desc = trim((string)($row['description'] ?? '')) !== '' ? $e($row['description']) : '—';
            $preview = $e($row['preview_url'] ?: $row['url']);
            $confirm = htmlspecialchars("Delete this media attachment?", ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $rows .= "<tr>
              <td><img src='{$preview}' alt='' style='width:56px;height:56px;object-fit:cover;border-radius:8px;border:1px solid var(--border)'></td>
              <td class='td-mono'>@{$e($row['username'] ?? 'unknown')}</td>
              <td><span class='badge badge-dim'>{$e($row['type'])}</span> {$attached}</td>
              <td class='td-dim' style='max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{$desc}</td>
              <td class='td-dim' style='font-size:.75rem'>{$e($this->fmtDate($row['created_at'] ?? ''))}</td>
              <td style='white-space:nowrap'>
                <a class='btn btn-sm btn-ghost' href='{$e($row['url'])}' target='_blank' rel='noopener'>Open</a>
                <form method='POST' action='/admin/media/{$e($row['id'])}/delete' style='display:inline' onsubmit='return confirm(\"{$confirm}\")'>
                  <button class='btn btn-sm btn-danger'>Delete</button>
                </form>
              </td>
            </tr>";
        }
        if ($rows === '') {
            $rows = "<tr><td colspan='6' style='text-align:center;color:var(--text3);padding:1.5rem'>No media matched the current filter.</td></tr>";
        }

        $typeOpts = "<option value='all'>All types</option>";
        foreach ($data['types'] as $rowType) {
            $sel = $rowType === $type ? ' selected' : '';
            $typeOpts .= "<option value='{$e($rowType)}'{$sel}>{$e($rowType)}</option>";
        }
        $checked = $orphans ? ' checked' : '';
        $pager = $this->paginator($data['page'], $data['pages'], '/admin/media?q=' . urlencode($q) . '&type=' . urlencode($type) . ($orphans ? '&orphans=1' : ''));

        return <<<HTML
<div class="form-row">
  <form method="GET" action="/admin/media" style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:flex-end">
    <div class="form-group">
      <label>Search</label>
      <input type="text" name="q" value="{$e($q)}" placeholder="username, alt text, URL">
    </div>
    <div class="form-group">
      <label>Type</label>
      <select name="type">{$typeOpts}</select>
    </div>
    <div class="form-group">
      <label>&nbsp;</label>
      <label style="display:flex;align-items:center;gap:.45rem;cursor:pointer;text-transform:none;letter-spacing:0">
        <input type="checkbox" name="orphans" value="1"{$checked}> Orphans only
      </label>
    </div>
    <div class="form-group"><label>&nbsp;</label><button class="btn btn-primary" type="submit">Filter</button></div>
  </form>
</div>
<div style="font-size:.75rem;color:var(--text3);margin-bottom:.8rem">{$e($data['total'])} attachments</div>
<div class="tbl-wrap">
  <table>
    <thead><tr><th>Preview</th><th>Owner</th><th>Type</th><th>Description</th><th>Created</th><th></th></tr></thead>
    <tbody>{$rows}</tbody>
  </table>
</div>
{$pager}
HTML;
    }

    private function contentContent(): string
    {
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $privacy = AdminModel::instanceContent('privacy');
        $terms = AdminModel::instanceContent('terms');
        $rules = AdminModel::instanceRules();
        $rulesText = implode("\n", array_map(static fn(array $rule): string => (string)$rule['text'], $rules));

        return <<<HTML
<div class="section">
  <div class="section-title">Public pages and rules</div>
  <form method="POST" action="/admin/content">
    <div class="form-row">
      <div class="form-group" style="min-width:280px">
        <label>Privacy page title</label>
        <input type="text" name="privacy_title" value="{$e($privacy['title'] ?? 'Privacy policy')}">
      </div>
      <div class="form-group" style="min-width:280px">
        <label>Terms page title</label>
        <input type="text" name="terms_title" value="{$e($terms['title'] ?? 'Terms of service')}">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1 1 48%">
        <label>Privacy policy</label>
        <textarea name="privacy_body" rows="12" style="width:100%;resize:vertical">{$e($privacy['body'] ?? '')}</textarea>
      </div>
      <div class="form-group" style="flex:1 1 48%">
        <label>Terms of service</label>
        <textarea name="terms_body" rows="12" style="width:100%;resize:vertical">{$e($terms['body'] ?? '')}</textarea>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1 1 100%">
        <label>Server rules</label>
        <textarea name="rules" rows="8" style="width:100%;resize:vertical" placeholder="One rule per line">{$e($rulesText)}</textarea>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>&nbsp;</label>
        <button class="btn btn-primary" type="submit">Save content</button>
      </div>
    </div>
  </form>
</div>
<div class="section">
  <div class="section-title">Public URLs</div>
  <div class="card" style="max-width:860px">
    <div class="card-sub">
      <a href="/privacy">/privacy</a> ·
      <a href="/terms">/terms</a> ·
      <a href="/rules">/rules</a>
    </div>
  </div>
</div>
HTML;
    }

    private function reportsContent(array $data, string $status): string
    {
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $statusOptions = ['all' => 'All', 'open' => 'Open', 'investigating' => 'Investigating', 'resolved' => 'Resolved', 'dismissed' => 'Dismissed'];
        $statusSelect = '';
        foreach ($statusOptions as $value => $label) {
            $sel = $value === $status ? ' selected' : '';
            $statusSelect .= "<option value='{$e($value)}'{$sel}>{$e($label)}</option>";
        }

        $rows = '';
        foreach ($data['rows'] as $row) {
            $statusBadgeClass = match ($row['status']) {
                'resolved' => 'badge-green',
                'dismissed' => 'badge-dim',
                'investigating' => 'badge-amber',
                default => 'badge-red',
            };
            $openSel = $row['status'] === 'open' ? ' selected' : '';
            $investigatingSel = $row['status'] === 'investigating' ? ' selected' : '';
            $resolvedSel = $row['status'] === 'resolved' ? ' selected' : '';
            $dismissedSel = $row['status'] === 'dismissed' ? ' selected' : '';
            $rows .= "<tr>
              <td class='td-mono'>{$e($row['target_kind'])}<br><span class='td-dim' style='font-size:.75rem'>{$e($row['target_label'])}</span></td>
              <td>{$e($row['reason'])}</td>
              <td><span class='badge {$statusBadgeClass}'>{$e($row['status'])}</span></td>
              <td class='td-dim'>{$e($row['reporter_username'] ?? 'admin')}</td>
              <td class='td-dim' style='font-size:.75rem'>{$e($this->fmtDate($row['created_at'] ?? ''))}</td>
              <td style='padding:0'>
                <form method='POST' action='/admin/reports/{$e($row['id'])}/update' class='form-row' style='padding:.85rem;gap:.5rem;align-items:flex-end'>
                  <div class='form-group'>
                    <label>Status</label>
                    <select name='status'>
                      <option value='open'{$openSel}>Open</option>
                      <option value='investigating'{$investigatingSel}>Investigating</option>
                      <option value='resolved'{$resolvedSel}>Resolved</option>
                      <option value='dismissed'{$dismissedSel}>Dismissed</option>
                    </select>
                  </div>
                  <div class='form-group'>
                    <label>Action</label>
                    <input type='text' name='moderation_action' value='{$e($row['moderation_action'] ?? '')}' placeholder='suspend, delete, warn...'>
                  </div>
                  <div class='form-group' style='flex:1 1 220px'>
                    <label>Resolution note</label>
                    <input type='text' name='resolution_note' value='{$e($row['resolution_note'] ?? '')}' placeholder='Optional note'>
                  </div>
                  <div class='form-group'>
                    <label>&nbsp;</label>
                    <button class='btn btn-sm btn-primary'>Save</button>
                  </div>
                </form>
              </td>
            </tr>";
            if (trim((string)($row['comment'] ?? '')) !== '') {
                $rows .= "<tr><td colspan='6' class='td-dim' style='background:var(--bg3);font-size:.8rem'>" . nl2br($e($row['comment'])) . "</td></tr>";
            }
        }
        if ($rows === '') {
            $rows = "<tr><td colspan='6' style='text-align:center;color:var(--text3);padding:1.5rem'>No reports yet.</td></tr>";
        }
        $pager = $this->paginator($data['page'], $data['pages'], '/admin/reports?status=' . urlencode($status));

        return <<<HTML
<div class="section">
  <div class="section-title">Create report</div>
  <form method="POST" action="/admin/reports/create">
    <div class="form-row">
      <div class="form-group">
        <label>Target type</label>
        <select name="target_kind">
          <option value="account">Account</option>
          <option value="status">Status</option>
          <option value="domain">Domain</option>
          <option value="other">Other</option>
        </select>
      </div>
      <div class="form-group" style="min-width:260px">
        <label>Target</label>
        <input type="text" name="target_label" placeholder="@user@example.com or post URL" required>
      </div>
      <div class="form-group" style="min-width:220px">
        <label>Reason</label>
        <input type="text" name="reason" placeholder="spam, harassment, abuse..." required>
      </div>
      <div class="form-group" style="flex:1 1 280px">
        <label>Details</label>
        <input type="text" name="comment" placeholder="Optional moderation context">
      </div>
      <div class="form-group">
        <label>&nbsp;</label>
        <button class="btn btn-primary" type="submit">Create report</button>
      </div>
    </div>
  </form>
</div>

<div class="form-row">
  <form method="GET" action="/admin/reports" style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:flex-end">
    <div class="form-group">
      <label>Status</label>
      <select name="status">{$statusSelect}</select>
    </div>
    <div class="form-group"><label>&nbsp;</label><button class="btn btn-ghost" type="submit">Filter</button></div>
  </form>
</div>
<div style="font-size:.75rem;color:var(--text3);margin-bottom:.8rem">{$e($data['total'])} reports</div>
<div class="tbl-wrap">
  <table>
    <thead><tr><th>Target</th><th>Reason</th><th>Status</th><th>Reporter</th><th>Created</th><th>Moderation</th></tr></thead>
    <tbody>{$rows}</tbody>
  </table>
</div>
{$pager}
HTML;
    }

    // ── Federation content ────────────────────────────────────

    private function federationContent(array $domains, array $blocked, string $q): string
    {
        $e    = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $rows = '';
        foreach ($domains['rows'] as $d) {
            $isBlocked  = (bool)$d['blocked'];
            $badge      = $isBlocked ? "<span class='badge badge-red'>blocked</span>" : "<span class='badge badge-green'>federated</span>";
            $action     = $isBlocked ? 'unblock' : 'block';
            $btnLabel   = $isBlocked ? 'Unblock' : 'Block';
            $btnCls     = $isBlocked ? 'btn-green' : 'btn-danger';
            $rows .= "<tr>
              <td class='td-mono'>{$e($d['domain'])}</td>
              <td class='td-dim'>{$e($d['actor_count'])}</td>
              <td class='td-dim' style='font-size:.7rem'>{$e(substr($d['last_seen'],0,10))}</td>
              <td>$badge</td>
              <td><form method='POST' action='/admin/federation'>
                <input type='hidden' name='action' value='$action'>
                <input type='hidden' name='domain' value='{$e($d['domain'])}'>
                <button class='btn btn-sm $btnCls'>$btnLabel</button>
              </form></td>
            </tr>";
        }

        // Blocked list
        $blockedRows = '';
        foreach ($blocked as $b) {
            $blockedRows .= "<tr>
              <td class='td-mono'>{$e($b['domain'])}</td>
              <td class='td-dim'>{$e($b['admin_name'] ?? '—')}</td>
              <td class='td-dim' style='font-size:.7rem'>{$e($this->fmtDate($b['created_at'] ?? ''))}</td>
              <td><form method='POST' action='/admin/federation'>
                <input type='hidden' name='action' value='unblock'>
                <input type='hidden' name='domain' value='{$e($b['domain'])}'>
                <button class='btn btn-sm btn-green'>Unblock</button>
              </form></td>
            </tr>";
        }
        if (!$blockedRows) $blockedRows = "<tr><td colspan='4' style='color:var(--text3);text-align:center;padding:1.5rem'>No blocked domains</td></tr>";

        $pager = $this->paginator($domains['page'], $domains['pages'], "/admin/federation?q=" . urlencode($q));

        return <<<HTML
<div class="section">
  <div class="section-title">Block a domain manually</div>
  <form method="POST" action="/admin/federation" class="form-row">
    <input type="hidden" name="action" value="block">
    <div class="form-group">
      <label>Domain</label>
      <input type="text" name="domain" placeholder="example.social" style="width:220px">
    </div>
    <div class="form-group"><label>&nbsp;</label><button class="btn btn-danger">Block domain</button></div>
  </form>
</div>

<div class="section">
  <div class="section-title">Refetch actor now</div>
  <form method="POST" action="/admin/federation/refetch-actor" class="form-row">
    <div class="form-group" style="min-width:420px">
      <label>Actor URL</label>
      <input type="url" name="actor_url" placeholder="https://example.social/users/alice" style="width:100%" required>
    </div>
    <div class="form-group"><label>&nbsp;</label><button class="btn btn-primary">Refetch actor</button></div>
  </form>
</div>

<div class="section">
  <div class="section-title">Blocked domains ({$e(count($blocked))})</div>
  <div class="tbl-wrap">
    <table><thead><tr><th>Domain</th><th>Blocked by</th><th>Date</th><th></th></tr></thead>
    <tbody>{$blockedRows}</tbody></table>
  </div>
</div>

<div class="section">
  <div class="section-title">Known instances ({$e($domains['total'])})</div>
  <form method="GET" action="/admin/federation" class="form-row" style="margin-bottom:.8rem">
    <input type="text" name="q" value="{$e($q)}" placeholder="filter by domain..." style="width:220px">
    <button class="btn btn-ghost" type="submit">Filter</button>
  </form>
  <div class="tbl-wrap">
    <table><thead><tr><th>Domain</th><th>Actors</th><th>Last contact</th><th>Status</th><th>Action</th></tr></thead>
    <tbody>{$rows}</tbody></table>
  </div>
  {$pager}
</div>
HTML;
    }

    private function settingsContent(): string
    {
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $generated = $this->readGeneratedConfig();
        $siteName = $generated['name'] ?? AP_NAME;
        $baseUrl = $generated['base_url'] ?? AP_BASE_URL;
        $adminEmail = $generated['admin_email'] ?? AP_ADMIN_EMAIL;
        $description = $generated['description'] ?? AP_DESCRIPTION;
        $sourceUrl = $generated['source_url'] ?? AP_SOURCE_URL;
        $atprotoDid = $generated['atproto_did'] ?? AP_ATPROTO_DID;
        $oauthTokenTtlDays = (int)($generated['oauth_token_ttl_days'] ?? oauth_token_ttl_days());
        $openReg = !empty($generated['open_reg']) || AP_OPEN_REG;
        $openChecked = $openReg ? ' checked' : '';
        $health = runtime_health_report(true);
        $install = install_security_report();
        $healthCards = [
            ['label' => 'DB writable', 'value' => !empty($health['checks']['db_writable']) ? 'Yes' : 'No'],
            ['label' => 'Runtime writable', 'value' => !empty($health['checks']['runtime_writable']) ? 'Yes' : 'No'],
            ['label' => 'Media writable', 'value' => !empty($health['checks']['media_writable']) ? 'Yes' : 'No'],
            ['label' => 'Auto maintenance', 'value' => !empty($health['checks']['auto_maintenance_enabled']) ? 'Enabled' : 'Disabled'],
            ['label' => 'Queue due', 'value' => (string)($health['details']['delivery_queue_due'] ?? 'n/a')],
            ['label' => 'Token TTL', 'value' => $oauthTokenTtlDays > 0 ? $oauthTokenTtlDays . ' days' : 'Disabled'],
        ];
        $healthCardsHtml = '';
        foreach ($healthCards as $card) {
            $healthCardsHtml .= "<div class='card'><div class='card-label'>{$e($card['label'])}</div><div class='card-value'>{$e($card['value'])}</div></div>";
        }
        $installHtml = '';
        foreach ($install['checks'] as $check) {
            $badge = $check['result'] === 'blocked'
                ? 'badge-green'
                : ($check['result'] === 'exposed' ? 'badge-red' : 'badge-amber');
            $label = $check['result'] === 'blocked'
                ? 'BLOCKED'
                : ($check['result'] === 'exposed' ? 'EXPOSED' : 'UNCLEAR');
            $status = $check['status'] !== null ? 'HTTP ' . (int)$check['status'] : 'No HTTP status';
            $installHtml .= "<div class='card' style='margin-bottom:.75rem'><div style='display:flex;gap:.5rem;align-items:center;margin-bottom:.45rem;flex-wrap:wrap'><span class='badge {$badge}'>{$label}</span><span class='card-label'>{$e($check['label'])}</span><span class='card-sub'>{$e($status)}</span></div><div class='card-sub'>{$e($check['message'])}</div><div class='card-sub' style='margin-top:.35rem'><code>{$e($check['path'])}</code></div></div>";
        }
        if ($installHtml === '') {
            $installHtml = "<div class='card'><div class='card-sub'>No live install checks were available.</div></div>";
        }
        $installNotesHtml = '';
        foreach ($install['notes'] as $note) {
            $installNotesHtml .= "<div class='card-sub' style='margin-top:.45rem'>{$e($note)}</div>";
        }

        return <<<HTML
<div class="section">
  <div class="section-title">Runtime health</div>
  <div class="cards" style="margin-bottom:1rem">{$healthCardsHtml}</div>
  <div class="card">
    <div class="card-sub">Health JSON is also available to administrators at <code>/api/v1/instance/health</code>.</div>
  </div>
</div>

<div class="section">
  <div class="section-title">Install hardening</div>
  {$installHtml}
  <div class="card">{$installNotesHtml}</div>
</div>

<div class="section">
  <div class="section-title">Instance settings</div>
  <form method="POST" action="/admin/settings" class="form-row">
    <div class="form-group" style="min-width:260px">
      <label>Site name</label>
      <input type="text" name="site_name" value="{$e($siteName)}" required>
    </div>
    <div class="form-group" style="min-width:320px">
      <label>Base URL</label>
      <input type="url" name="base_url" value="{$e($baseUrl)}" placeholder="https://example.com" required>
    </div>
    <div class="form-group" style="min-width:260px">
      <label>Administrator email</label>
      <input type="email" name="admin_email" value="{$e($adminEmail)}" required>
    </div>
    <div class="form-group" style="flex:1 1 100%">
      <label>Description</label>
      <textarea name="description" rows="4" style="width:100%;padding:.75rem .9rem;background:var(--bg2);border:1px solid var(--border);border-radius:12px;color:var(--text);font:inherit;resize:vertical">{$e($description)}</textarea>
    </div>
    <div class="form-group" style="min-width:320px">
      <label>Source URL</label>
      <input type="url" name="source_url" value="{$e($sourceUrl)}" placeholder="https://github.com/your-org/starling">
    </div>
    <div class="form-group" style="min-width:320px">
      <label>AT Protocol DID</label>
      <input type="text" name="atproto_did" value="{$e($atprotoDid)}" placeholder="did:plc:...">
    </div>
    <div class="form-group" style="min-width:220px">
      <label>OAuth token max age (days)</label>
      <input type="number" min="0" max="3650" name="oauth_token_ttl_days" value="{$e($oauthTokenTtlDays)}" placeholder="0">
    </div>
    <div class="form-group" style="min-width:180px">
      <label>&nbsp;</label>
      <label style="display:flex;align-items:center;gap:.45rem;cursor:pointer;text-transform:none;letter-spacing:0">
        <input type="checkbox" name="open_reg" value="1"{$openChecked}> Open registrations
      </label>
    </div>
    <div class="form-group">
      <label>&nbsp;</label>
      <button class="btn btn-primary" type="submit">Save settings</button>
    </div>
  </form>
</div>

<div class="section">
  <div class="section-title">Notes</div>
  <div class="card" style="max-width:860px">
    <div class="card-sub">These settings are stored in <code>storage/config.generated.php</code>. Changing the base URL or domain after federation has already started can break identifiers and remote references, so do that only with care.</div>
    <div class="card-sub" style="margin-top:.55rem">OAuth token max age is disabled when set to <code>0</code>. When enabled, tokens are revoked lazily on their next authenticated use.</div>
  </div>
</div>
HTML;
    }

    // ── Inbox log content ─────────────────────────────────────

    private function inboxLogContent(array $data, string $type, bool $errors): string
    {
        $e    = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $rows = '';
        foreach ($data['rows'] as $r) {
            $hasErr  = $r['error'] !== '';
            $errBadge= $hasErr ? "<span class='badge badge-red'>error</span>" : "<span class='badge badge-green'>ok</span>";
            $requestLine = trim((string)($r['request_method'] ?? '')) !== ''
                ? $e(trim((string)$r['request_method']) . ' ' . trim((string)($r['request_path'] ?? '')))
                : '—';
            $remoteIp = trim((string)($r['remote_ip'] ?? '')) !== '' ? $e($r['remote_ip']) : '—';
            $rows .= "<tr>
              <td class='td-mono' style='font-size:.7rem'>{$e($this->fmtDateTime($r['created_at'] ?? ''))}</td>
              <td><span class='badge badge-blue'>{$e($r['type'])}</span></td>
              <td class='td-mono td-dim' style='font-size:.7rem;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{$e($r['actor_url'])}</td>
              <td class='td-mono td-dim' style='font-size:.68rem;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{$requestLine}</td>
              <td class='td-mono td-dim' style='font-size:.68rem'>{$remoteIp}</td>
              <td>$errBadge</td>
              <td><a href='/admin/inbox-log/{$e($r['id'])}' class='btn btn-sm btn-ghost'>View</a></td>
            </tr>";
        }

        $typeOpts = "<option value=''>All types</option>";
        foreach ($data['types'] as $t) {
            $sel      = $type === $t ? ' selected' : '';
            $typeOpts .= "<option value='{$e($t)}'{$sel}>{$e($t)}</option>";
        }
        $errChecked = $errors ? ' checked' : '';
        $pager = $this->paginator($data['page'], $data['pages'], "/admin/inbox-log?type=" . urlencode($type) . ($errors ? '&errors=1' : ''));

        return <<<HTML
<div class="form-row">
  <form method="GET" action="/admin/inbox-log" style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:flex-end">
    <div class="form-group">
      <label>Type</label>
      <select name="type">{$typeOpts}</select>
    </div>
    <div class="form-group">
      <label>&nbsp;</label>
      <label style="display:flex;align-items:center;gap:.4rem;cursor:pointer;text-transform:none;letter-spacing:0">
        <input type="checkbox" name="errors" value="1"{$errChecked}> Errors only
      </label>
    </div>
    <div class="form-group"><label>&nbsp;</label><button class="btn btn-ghost" type="submit">Filter</button></div>
  </form>
</div>
<div style="font-size:.75rem;color:var(--text3);margin-bottom:.8rem">{$e($data['total'])} entries</div>
<div class="tbl-wrap">
  <table>
    <thead><tr><th>Date</th><th>Type</th><th>Actor</th><th>Request</th><th>IP</th><th>Status</th><th></th></tr></thead>
    <tbody>{$rows}</tbody>
  </table>
</div>
{$pager}
HTML;
    }

    private function inboxDetailContent(array $r): string
    {
        $e    = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $json = json_encode(json_decode($r['raw_json']), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $sigHeaders = json_decode((string)($r['sig_headers'] ?? '{}'), true);
        $sigDebug = json_decode((string)($r['sig_debug'] ?? '{}'), true);
        $sigJson = '';
        if (is_array($sigHeaders) && $sigHeaders) {
            $sigJson = json_encode($sigHeaders, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        $sigDebugJson = '';
        if (is_array($sigDebug) && $sigDebug) {
            $sigDebugJson = json_encode($sigDebug, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        $requestParts = [];
        if (($r['request_method'] ?? '') !== '' || ($r['request_path'] ?? '') !== '') {
            $requestParts[] = trim((string)($r['request_method'] ?? '')) . ' ' . trim((string)($r['request_path'] ?? ''));
        }
        if (($r['request_host'] ?? '') !== '') {
            $requestParts[] = 'host=' . trim((string)$r['request_host']);
        }
        if (($r['remote_ip'] ?? '') !== '') {
            $requestParts[] = 'ip=' . trim((string)$r['remote_ip']);
        }
        $requestSummary = $requestParts ? implode(' · ', array_filter($requestParts)) : '—';
        $actorUrl = trim((string)($r['actor_url'] ?? ''));
        $errHtml = $r['error'] ? "<div class='flash flash-error' style='margin-bottom:1rem'><strong>Error:</strong> {$e($r['error'])}</div>" : '';
        $sigHtml = $sigJson !== '' ? "<div class=\"section-title\">Signature headers</div>\n<pre class=\"code\">{$e($sigJson)}</pre>" : '';
        $sigDebugHtml = $sigDebugJson !== '' ? "<div class=\"section-title\">Signature debug</div>\n<pre class=\"code\">{$e($sigDebugJson)}</pre>" : '';
        $retryForm = "<form method=\"POST\" action=\"/admin/inbox-log/{$e($r['id'])}/retry\" style=\"display:inline-flex\"><button class=\"btn btn-primary btn-sm\" type=\"submit\">Retry verification</button></form>";
        $refetchForm = $actorUrl !== ''
            ? "<form method=\"POST\" action=\"/admin/federation/refetch-actor\" style=\"display:inline-flex\"><input type=\"hidden\" name=\"actor_url\" value=\"{$e($actorUrl)}\"><button class=\"btn btn-ghost btn-sm\" type=\"submit\">Refetch actor now</button></form>"
            : '';

        return <<<HTML
<div style="margin-bottom:1rem;display:flex;gap:.6rem;flex-wrap:wrap;align-items:center"><a href="/admin/inbox-log" class="btn btn-ghost btn-sm">← Back</a>{$retryForm}{$refetchForm}</div>
{$errHtml}
<div class="cards" style="grid-template-columns:repeat(3,auto) 1fr;gap:.6rem;margin-bottom:1.5rem">
  <div class="card"><div class="card-label">Type</div><div style="color:var(--blue);font-weight:600">{$e($r['type'])}</div></div>
  <div class="card"><div class="card-label">Date</div><div class="card-value" style="font-size:.9rem">{$e($this->fmtDateTime($r['created_at'] ?? ''))}</div></div>
  <div class="card"><div class="card-label">Actor</div><div class="card-value" style="font-size:.7rem;word-break:break-all">{$e($r['actor_url'])}</div></div>
  <div class="card"><div class="card-label">Request</div><div class="card-value" style="font-size:.72rem;word-break:break-all">{$e($requestSummary)}</div></div>
</div>
{$sigHtml}
{$sigDebugHtml}
<div class="section-title">Raw activity JSON</div>
<pre class="code">{$e($json)}</pre>
HTML;
    }

    // ── Maintenance content ───────────────────────────────────

    private function maintenanceContent(array $disk): string
    {
        $e  = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $fb = fn($b) => AdminModel::formatBytes((int)$b);
        $d  = AdminModel::AGGRESSIVE_DEFAULTS;
        $autoEnabled = AdminModel::isAutoMaintenanceEnabled();
        $autoStateColor = $autoEnabled ? 'var(--green)' : 'var(--amber)';
        $autoStateLabel = $autoEnabled ? 'enabled' : 'disabled';
        $autoToggleValue = $autoEnabled ? '0' : '1';
        $autoToggleBtnClass = $autoEnabled ? 'btn-danger' : 'btn-primary';
        $autoToggleBtnLabel = $autoEnabled ? 'Disable automatic maintenance' : 'Enable automatic maintenance';

        // Disk usage bar
        $used   = $disk['totalSpace'] - $disk['freeSpace'];
        $pct    = $disk['totalSpace'] > 0 ? min(100, round($used / $disk['totalSpace'] * 100)) : 0;
        $cls    = $pct > 85 ? 'red' : ($pct > 65 ? '' : 'green');

        // Table stats
        $tableRows = '';
        arsort($disk['tableStats']);
        foreach ($disk['tableStats'] as $tbl => $cnt) {
            $tableRows .= "<tr><td class='td-mono'>{$e($tbl)}</td><td class='td-dim'>{$e($cnt)} rows</td></tr>";
        }
        $statusRows = '';
        foreach ([
            'Local statuses' => $disk['localStatusRows'] ?? 0,
            'Remote statuses' => $disk['remoteStatusRows'] ?? 0,
            'Remote from followed actors' => $disk['remoteFollowedStatusRows'] ?? 0,
            'Remote from unfollowed actors' => $disk['remoteUnfollowedStatusRows'] ?? 0,
            'Followed remote candidates >' . $d['followed_remote_posts_days'] . 'd' => $disk['followedRemotePostsOld'] ?? 0,
            'Followed remote prunable >' . $d['followed_remote_posts_days'] . 'd' => $disk['followedRemotePostsPrunable'] ?? 0,
            'Followed remote protected >' . $d['followed_remote_posts_days'] . 'd' => $disk['followedRemotePostsProtected'] ?? 0,
            'Unfollowed remote candidates >' . $d['remote_posts_days'] . 'd' => $disk['remotePostsOld'] ?? 0,
            'Unfollowed remote prunable >' . $d['remote_posts_days'] . 'd' => $disk['remotePostsPrunable'] ?? 0,
        ] as $label => $cnt) {
            $statusRows .= "<tr><td>{$e($label)}</td><td class='td-dim'>{$e($cnt)} rows</td></tr>";
        }

        return <<<HTML
<div class="section">
  <div class="section-title">Disk usage</div>
  <div style="max-width:600px">
    <div style="display:flex;justify-content:space-between;font-size:.75rem;color:var(--text2);margin-bottom:.3rem">
      <span>Server disk</span>
      <span>{$fb($used)} used of {$fb($disk['totalSpace'])} ({$pct}%)</span>
    </div>
    <div class="disk-bar-wrap"><div class="disk-bar-fill {$cls}" style="width:{$pct}%"></div></div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:.5rem;margin-top:.8rem;font-size:.75rem">
      <div style="color:var(--text2)">Database<br><strong style="color:var(--text)">{$fb($disk['dbSize'])}</strong></div>
      <div style="color:var(--text2)">Media ({$e($disk['mediaCount'])} files)<br><strong style="color:var(--text)">{$fb($disk['mediaSize'])}</strong></div>
      <div style="color:var(--text2)">Runtime ({$e($disk['runtimeCount'])} items)<br><strong style="color:var(--text)">{$fb($disk['runtimeSize'])}</strong></div>
      <div style="color:var(--text2)">Free<br><strong style="color:var(--green)">{$fb($disk['freeSpace'])}</strong></div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Potentially recoverable space</div>
  <div class="cards" style="grid-template-columns:repeat(3,auto);gap:.6rem">
    <div class="card amber"><div class="card-label">Prunable inbox log &gt;{$e($d['inbox_days'])}d</div><div class="card-value">{$fb($disk['inboxLogSize'])}</div></div>
    <div class="card"><div class="card-label">Unfollowed remote posts</div><div class="card-value">{$e($disk['remotePostsPrunable'])}</div><div class="card-sub">from {$e($disk['remotePostsOld'])} candidates &gt;{$e($d['remote_posts_days'])}d</div></div>
    <div class="card amber"><div class="card-label">Followed remote posts</div><div class="card-value">{$e($disk['followedRemotePostsPrunable'])}</div><div class="card-sub">from {$e($disk['followedRemotePostsOld'])} candidates &gt;{$e($d['followed_remote_posts_days'])}d · {$e($disk['followedRemotePostsProtected'])} protected</div></div>
    <div class="card"><div class="card-label">Prunable orphaned media</div><div class="card-value">{$e($disk['orphanMedia'])}</div><div class="card-sub">files &gt;{$e($d['orphan_media_hours'])}h</div></div>
    <div class="card"><div class="card-label">Prunable runtime</div><div class="card-value">{$e($disk['runtimePrunable'])}</div><div class="card-sub">files &gt;{$e($d['runtime_days'])}d</div></div>
  </div>
</div>

<div class="section">
  <div class="section-title">Full cleanup</div>
  <div class="maint-card" style="border-color:var(--blue);margin-bottom:1.5rem">
    <h3>🧹 Full cleanup (aggressive space-saving mode)</h3>
    <p>Runs every cleanup operation in sequence with aggressive defaults for very small shared-hosting instances: inbox log &gt;{$e($d['inbox_days'])}d, unfollowed remote posts &gt;{$e($d['remote_posts_days'])}d, followed remote posts &gt;{$e($d['followed_remote_posts_days'])}d (protects bookmarks, favourites, notifications, pins, active polls, and locally referenced posts), actors &gt;{$e($d['remote_actors_days'])}d, notifications &gt;{$e($d['notifications_days'])}d, orphaned media &gt;{$e($d['orphan_media_hours'])}h, OAuth tokens &gt;{$e($d['tokens_days'])}d, link cards &gt;{$e($d['link_cards_days'])}d, and old runtime artifacts &gt;{$e($d['runtime_days'])}d. If the cleanup frees enough space, database compaction (VACUUM) starts automatically in the background right after it finishes.</p>
    <form method="POST" action="/admin/maintenance">
      <input type="hidden" name="action" value="prune_all">
      <button class="btn btn-primary">Run full cleanup</button>
    </form>
  </div>
  <div class="maint-card" style="margin-bottom:1.5rem">
    <h3>🌙 Automatic maintenance without cron</h3>
    <p>This instance tries to run aggressive cleanup automatically on the first normal request after 03:00 local time. If the database is large and cleanup removed enough data, database compaction (VACUUM) may also start in the background. Because there is no cron job or resident worker, this is opportunistic and only runs when there is traffic during that time window.</p>
    <p style="margin-top:.6rem;color:{$autoStateColor}">Current state: <strong>{$e($autoStateLabel)}</strong></p>
    <form method="POST" action="/admin/maintenance" style="margin-top:.7rem">
      <input type="hidden" name="action" value="toggle_auto_maintenance">
      <input type="hidden" name="enable" value="{$e($autoToggleValue)}">
      <button class="btn {$autoToggleBtnClass}">{$e($autoToggleBtnLabel)}</button>
    </form>
  </div>
</div>

<div class="section">
  <div class="section-title">Individual operations</div>
  <div class="maint-grid">

    <div class="maint-card">
      <h3>🗂 Inbox Log</h3>
      <p>The inbox log stores every received ActivityPub activity as raw JSON. It grows continuously and is the main source of database growth.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_inbox">
        <label style="font-size:.75rem;color:var(--text2)">Delete entries older than</label>
        <input type="number" name="days" value="{$e($d['inbox_days'])}" min="1"> days
        <button class="btn btn-danger">Clean up</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>📨 Remote posts</h3>
      <p>Posts from remote actors no local user currently follows. Protected local references are kept.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_remote_posts">
        <label style="font-size:.75rem;color:var(--text2)">Delete remote posts older than</label>
        <input type="number" name="days" value="{$e($d['remote_posts_days'])}" min="1"> days
        <button class="btn btn-danger">Clean up</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>📮 Followed remote posts</h3>
      <p>Old cached home timeline posts from actors still followed locally. Keeps bookmarks, favourites, notifications, pins, active polls, and posts referenced by local replies, boosts, or quotes.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_followed_remote_posts">
        <label style="font-size:.75rem;color:var(--text2)">Delete followed remote posts older than</label>
        <input type="number" name="days" value="{$e($d['followed_remote_posts_days'])}" min="1"> days
        <button class="btn btn-danger">Clean up</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>👤 Remote actors</h3>
      <p>Cached profiles from other instances. Removes actors that no local user follows and that have not been seen recently.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_remote_actors">
        <label style="font-size:.75rem;color:var(--text2)">Remove actors not seen for more than</label>
        <input type="number" name="days" value="{$e($d['remote_actors_days'])}" min="1"> days
        <button class="btn btn-danger">Clean up</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>🖼 Orphaned media</h3>
      <p>Media files that were uploaded but never attached to a post (abandoned uploads older than {$e($d['orphan_media_hours'])}h).</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_orphan_media">
        <label style="font-size:.75rem;color:var(--text2)">Delete abandoned uploads older than</label>
        <input type="number" name="hours" value="{$e($d['orphan_media_hours'])}" min="1"> hours
        <button class="btn btn-danger">Clean orphaned media</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>🔔 Old notifications</h3>
      <p>Notifications (mentions, follows, favourites) older than the selected number of days.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_notifications">
        <label style="font-size:.75rem;color:var(--text2)">Delete notifications older than</label>
        <input type="number" name="days" value="{$e($d['notifications_days'])}" min="1"> days
        <button class="btn btn-danger">Clean up</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>🔑 Tokens OAuth</h3>
      <p>Access tokens from old sessions. Removes tokens created more than {$e($d['tokens_days'])} days ago (inactive sessions).</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_tokens">
        <label style="font-size:.75rem;color:var(--text2)">Delete tokens older than</label>
        <input type="number" name="days" value="{$e($d['tokens_days'])}" min="1"> days
        <button class="btn btn-ghost">Clean old tokens</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>🗑 Delete remote post</h3>
      <p>Deletes one specific remote post from the cache, including its attachments and reblogs. Useful for removing quoted or inappropriate posts stored locally. Paste the post ActivityPub URL or URI.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="delete_remote_post">
        <label style="font-size:.75rem;color:var(--text2)">Post URI (for example: https://mastodon.social/users/x/statuses/123)</label>
        <input type="text" name="uri" placeholder="https://..." style="width:100%">
        <button class="btn btn-danger">Delete post</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>🔗 Link cards (cache OGP)</h3>
      <p>Open Graph card cache (title, image, description) for links shared in posts. These cards can be fetched again automatically when the link is shared in the future.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_link_cards">
        <label style="font-size:.75rem;color:var(--text2)">Delete cards older than</label>
        <input type="number" name="days" value="{$e($d['link_cards_days'])}" min="1"> days
        <button class="btn btn-danger">Clean up</button>
      </form>
    </div>

    <div class="maint-card">
      <h3>🧰 Temporary runtime</h3>
      <p>Temporary and operational artifacts in <code>storage/runtime</code>, such as short-lived DNS caches, throttle locks, and local test reports. Cleanup is conservative and does not touch critical files like <code>queue_wake.key</code>, <code>vacuum.lock</code>, <code>auto_maintenance.disabled</code>, or the directory itself.</p>
      <form method="POST" action="/admin/maintenance" class="maint-form">
        <input type="hidden" name="action" value="prune_runtime">
        <label style="font-size:.75rem;color:var(--text2)">Delete artifacts older than</label>
        <input type="number" name="days" value="{$e($d['runtime_days'])}" min="1"> days
        <button class="btn btn-ghost">Clean runtime</button>
      </form>
    </div>

    <div class="maint-card" style="border-color:var(--amber)">
      <h3>⚡ VACUUM — Compact database</h3>
      <p>SQLite does not automatically reclaim disk space after rows are deleted. VACUUM rebuilds the database and recovers that space physically.<br><br><strong style="color:var(--amber)">This may take a few seconds.</strong> The server becomes unavailable during the operation.</p>
      <form method="POST" action="/admin/maintenance">
        <input type="hidden" name="action" value="vacuum">
        <button class="btn btn-primary">Run VACUUM</button>
      </form>
    </div>

  </div>
</div>

<div class="section">
  <div class="section-title">Status rows breakdown</div>
  <div class="tbl-wrap" style="max-width:560px;margin-bottom:1.5rem">
    <table><thead><tr><th>Group</th><th>Rows</th></tr></thead>
    <tbody>{$statusRows}</tbody></table>
  </div>
  <div class="section-title">Rows per table</div>
  <div class="tbl-wrap" style="max-width:400px">
    <table><thead><tr><th>Table</th><th>Rows</th></tr></thead>
    <tbody>{$tableRows}</tbody></table>
  </div>
</div>
HTML;
    }

    // ── Delivery queue content ────────────────────────────────

    private function relaysContent(array $rows): string
    {
        $e    = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $csrf = $e($_SESSION['admin_csrf'] ?? '');

        $rowsHtml = '';
        foreach ($rows as $r) {
            $status = match ($r['status']) {
                'accepted' => '<span style="color:#2e7d32">● accepted</span>',
                'pending'  => '<span style="color:#e65100">● pending</span>',
                default    => $e($r['status']),
            };
            $receivesPosts = !empty($r['receive_posts']);
            $mode = $receivesPosts
                ? '<span style="color:#2e7d32">send + receive</span>'
                : '<span style="color:var(--text2)">send only</span>';
            $limitLabel = $receivesPosts
                ? $e($r['daily_limit']) . '/day'
                : '<span style="color:#888">disabled</span>';
            $toggleLabel = $receivesPosts ? 'Disable receiving' : 'Enable receiving';
            $rowsHtml .= "
            <tr>
                <td style='word-break:break-all'>{$e($r['actor_url'])}</td>
                <td>$status</td>
                <td>$mode</td>
                <td>$limitLabel</td>
                <td>{$e($this->fmtDate($r['created_at'] ?? ''))}</td>
                <td>
                    <form method='post' action='/admin/relays/action' style='display:inline-block;margin-right:.35rem'>
                        <input type='hidden' name='_csrf' value='$csrf'>
                        <input type='hidden' name='action' value='toggle_receive'>
                        <input type='hidden' name='relay_url' value='{$e($r['actor_url'])}'>
                        <button class='btn btn-sm btn-ghost'>$toggleLabel</button>
                    </form>
                    <form method='post' action='/admin/relays/action' onsubmit=\"return confirm('Remove relay?')\">
                        <input type='hidden' name='_csrf' value='$csrf'>
                        <input type='hidden' name='action' value='unsubscribe'>
                        <input type='hidden' name='relay_url' value='{$e($r['actor_url'])}'>
                        <button class='btn btn-sm btn-danger'>Remove</button>
                    </form>
                </td>
            </tr>";
        }
        if (!$rowsHtml) $rowsHtml = "<tr><td colspan='6' style='text-align:center;color:#888'>No subscribed relays.</td></tr>";

        return "
        <div class='card'>
            <h2>Subscribe to a relay</h2>
            <p style='color:#666;margin-bottom:1rem'>
                You can use relays only to send your public posts, or also to receive federated content.
                On a small shared-hosting instance, <strong>send only</strong> mode reduces database growth significantly.<br>
                Examples: <code>https://relay.fedi.buzz/actor</code> · <code>https://relay.activitypub.one/actor</code>
            </p>
            <form method='post' action='/admin/relays/action'>
                <input type='hidden' name='_csrf' value='$csrf'>
                <input type='hidden' name='action' value='subscribe'>
                <div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center'>
                    <input type='url' name='relay_url' placeholder='https://relay.fedi.buzz/actor'
                           style='flex:1;min-width:280px;padding:.5rem;border:1px solid #ccc;border-radius:6px'>
                    <label style='white-space:nowrap;color:#444'>Limit/day:
                        <input type='number' name='daily_limit' value='500' min='50' max='5000' step='50'
                               style='width:80px;padding:.45rem;border:1px solid #ccc;border-radius:6px;margin-left:.3rem'>
                    </label>
                    <label style='white-space:nowrap;color:#444'>
                        <input type='checkbox' name='receive_posts' value='1' checked>
                        Receive posts
                    </label>
                    <button class='btn'>Subscribe</button>
                </div>
                <p style='color:#888;font-size:.85rem;margin-top:.5rem'>
                    If receiving is disabled, the relay still delivers this instance's public posts to the fediverse.
                    In that mode, the daily limit is stored but not applied.
                </p>
            </form>
        </div>
        <div class='card' style='margin-top:1.5rem'>
            <h2>Active relays</h2>
            <table class='table'>
                <thead><tr><th>Actor URL</th><th>Status</th><th>Mode</th><th>Limit</th><th>Subscribed on</th><th>Action</th></tr></thead>
                <tbody>$rowsHtml</tbody>
            </table>
        </div>";
    }

    private function deliveryQueueContent(array $rows, array $stats, array $errorBuckets, array $topDomains, array $recentAttempts, array $recentBatches, array $batchStats, array $tuning, array $profiles, string $matchedProfile): string
    {
        $e   = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $now = time();

        $tableRows = '';
        foreach ($rows as $r) {
            $payload  = json_decode($r['payload'] ?? '{}', true);
            $type     = $e($payload['type'] ?? '—');
            $objType  = '';
            $objRef   = '';
            if (isset($payload['object'])) {
                $obj = $payload['object'];
                $objType = ' <span style="color:var(--text3);font-size:.7rem">(' . $e(is_array($obj) ? ($obj['type'] ?? '?') : 'ref') . ')</span>';
                $rawRef = '';
                if (is_array($obj)) {
                    $rawRef = (string)($obj['id'] ?? $obj['url'] ?? $obj['uri'] ?? '');
                } elseif (is_string($obj)) {
                    $rawRef = $obj;
                }
                if ($rawRef !== '') {
                    $label = $rawRef;
                    if (preg_match('~/(objects|@[^/]+/)([^/?#]+)$~', $rawRef, $m)) {
                        $label = $m[2];
                    } elseif (strlen($rawRef) > 72) {
                        $label = substr($rawRef, 0, 69) . '...';
                    }
                    $objRef = '<div class="td-dim" style="font-size:.68rem;max-width:260px;word-break:break-word;margin-top:.18rem" title="' . $e($rawRef) . '">obj: ' . $e($label) . '</div>';
                }
            }
            $domain   = $e(parse_url($r['inbox_url'], PHP_URL_HOST) ?? $r['inbox_url']);
            $attempts = (int)$r['attempts'];
            $lastBucket = trim((string)($r['last_error_bucket'] ?? ''));
            $isTerminalBucket = in_array($lastBucket, ['unsafe_url', 'dns_nxdomain', 'http_400', 'http_403', 'http_404', 'http_405', 'http_410', 'http_422'], true);
            $attClass = $attempts === 0 ? 'badge-green' : ($attempts >= 8 ? 'badge-red' : 'badge-amber');
            $attLabel = $attempts === 0
                ? 'pending'
                : ($attempts >= 8
                    ? ($isTerminalBucket ? 'terminal failure' : 'retries exhausted')
                    : "attempt $attempts");
            $lastCode = (int)($r['last_http_code'] ?? 0);
            $lastError = trim((string)($r['last_error'] ?? ''));
            $lastDetail = trim((string)($r['last_error_detail'] ?? ''));
            $lastBody = trim((string)($r['last_response_body'] ?? ''));
            $lastResult = $lastCode > 0 ? ('HTTP ' . $lastCode) : ($lastError !== '' ? $lastError : '—');
            if ($lastBucket !== '') {
                $lastResult .= ' · ' . $lastBucket;
            }
            if ($lastDetail !== '') {
                $lastResult .= ' · ' . $lastDetail;
            } elseif ($lastError !== '' && $lastCode > 0 && !str_starts_with($lastError, 'http_')) {
                $lastResult .= ' · ' . $lastError;
            }
            if ($lastBody !== '') {
                $lastResult .= ' · ' . $lastBody;
            }

            $nextTs  = strtotime($r['next_retry_at'] ?? '');
            $nextRel = $nextTs ? ($nextTs <= $now ? 'now' : 'in ' . gmdate('H\hi', $nextTs - $now)) : '—';

            $age = $this->fmtDateTimeShort($r['created_at'] ?? '');
            $lastAttempt = $this->fmtDateTimeShort($r['last_attempt_at'] ?? '');

            $tableRows .= "<tr>
              <td class='td-mono' style='font-size:.75rem'>$domain</td>
              <td>$type{$objType}{$objRef}</td>
              <td><span class='badge $attClass'>{$attLabel}</span></td>
              <td class='td-dim' style='font-size:.72rem;max-width:260px;word-break:break-word'>{$e($lastResult)}</td>
              <td class='td-dim' style='font-size:.75rem'>$nextRel</td>
              <td class='td-dim' style='font-size:.7rem'>{$e($lastAttempt)}</td>
              <td class='td-dim' style='font-size:.7rem'>{$e($age)}</td>
            </tr>";
        }

        if (!$tableRows) {
            $tableRows = "<tr><td colspan='7' style='text-align:center;color:var(--text3);padding:2rem'>Queue empty — all deliveries have been completed.</td></tr>";
        }

        $pendingColor  = $stats['pending']  > 0 ? 'var(--blue)'  : 'var(--green)';
        $retryingColor = $stats['retrying'] > 0 ? 'var(--amber)' : 'var(--green)';
        $failedColor   = $stats['failed']   > 0 ? 'var(--red)'   : 'var(--green)';
        $dueColor      = $stats['due']      > 0 ? 'var(--amber)' : 'var(--green)';
        $nextDueLabel  = $e($this->fmtDateTimeShort($stats['next_due'] ?? ''));
        $lastAttemptLabel = $e($this->fmtDateTimeShort($stats['last_attempt'] ?? ''));

        $bucketHtml = '';
        foreach ($errorBuckets as $row) {
            $bucketHtml .= '<div class="card-sub"><strong>' . $e($row['bucket'] ?? 'unknown') . '</strong>: ' . $e($row['c'] ?? 0) . "</div>";
        }
        if ($bucketHtml === '') $bucketHtml = '<div class="card-sub">No recorded failures.</div>';

        $domainHtml = '';
        foreach ($topDomains as $row) {
            $failedLabel = (int)($row['failed'] ?? 0) > 0 ? ' · failed ' . $e($row['failed']) : '';
            $domainHtml .= '<div class="card-sub"><strong>' . $e($row['domain'] ?? '—') . '</strong>: ' . $e($row['c'] ?? 0) . $failedLabel . "</div>";
        }
        if ($domainHtml === '') $domainHtml = '<div class="card-sub">No queued destinations.</div>';

        $attemptRows = '';
        foreach ($recentAttempts as $row) {
            $outcome = (string)($row['outcome'] ?? 'unknown');
            $outcomeClass = match ($outcome) {
                'success' => 'badge-green',
                'failed_terminal' => 'badge-red',
                default => 'badge-amber',
            };
            $outcomeLabel = match ($outcome) {
                'success' => 'ok',
                'failed_terminal' => 'terminal',
                'failed_retry' => 'retry',
                default => $outcome,
            };
            $httpCode = (int)($row['http_code'] ?? 0);
            $result = $httpCode > 0 ? ('HTTP ' . $httpCode) : '—';
            $bucket = trim((string)($row['error_bucket'] ?? ''));
            $detail = trim((string)($row['error_detail'] ?? ''));
            if ($bucket !== '' && $bucket !== 'success') $result .= ' · ' . $bucket;
            if ($detail !== '') $result .= ' · ' . $detail;
            $attemptRows .= "<tr>
              <td class='td-mono' style='font-size:.75rem'>" . $e($row['domain'] ?? (parse_url((string)($row['inbox_url'] ?? ''), PHP_URL_HOST) ?? '—')) . "</td>
              <td>" . $e($row['activity_type'] ?? '—') . " <span style='color:var(--text3);font-size:.7rem'>(" . $e($row['object_type'] ?? '—') . ")</span></td>
              <td><span class='badge {$outcomeClass}'>" . $e($outcomeLabel) . "</span></td>
              <td class='td-dim' style='font-size:.72rem;max-width:260px;word-break:break-word'>" . $e($result) . "</td>
              <td class='td-dim' style='font-size:.7rem'>" . $e($this->fmtDateTime($row['created_at'] ?? '')) . "</td>
            </tr>";
        }
        if ($attemptRows === '') {
            $attemptRows = "<tr><td colspan='5' style='text-align:center;color:var(--text3);padding:1.4rem'>No recent attempt history.</td></tr>";
        }

        $batchRows = '';
        foreach ($recentBatches as $row) {
            $batchRows .= "<tr>
              <td class='td-dim' style='font-size:.75rem'>" . $e($this->fmtDateTime($row['created_at'] ?? '')) . "</td>
              <td class='td-mono' style='font-size:.72rem'>limit " . $e($row['batch_limit'] ?? 0) . "</td>
              <td class='td-dim' style='font-size:.72rem'>leased " . $e($row['leased'] ?? 0) . " · processed " . $e($row['processed'] ?? 0) . "</td>
              <td class='td-dim' style='font-size:.72rem'>success " . $e($row['success'] ?? 0) . " · retry " . $e($row['retry'] ?? 0) . " · terminal " . $e($row['terminal'] ?? 0) . " · skipped " . $e($row['skipped'] ?? 0) . "</td>
              <td class='td-dim' style='font-size:.72rem'>" . (((int)($row['due_remaining'] ?? 0)) > 0 ? 'true' : 'false') . "</td>
              <td class='td-dim' style='font-size:.72rem'>" . $e(number_format(((int)($row['duration_ms'] ?? 0)) / 1000, 3, '.', '')) . "s</td>
            </tr>";
        }
        if ($batchRows === '') {
            $batchRows = "<tr><td colspan='6' style='text-align:center;color:var(--text3);padding:1.4rem'>No recent batch summaries recorded yet.</td></tr>";
        }

        $profileOptions = "<option value='custom'" . ($matchedProfile === 'custom' ? ' selected' : '') . ">Custom</option>";
        $profileCards = '';
        foreach ($profiles as $key => $profile) {
            $selected = $matchedProfile === $key ? ' selected' : '';
            $profileOptions .= "<option value='{$e($key)}'{$selected}>{$e($profile['label'] ?? $key)}</option>";
            $values = (array)($profile['values'] ?? []);
            $profileCards .= "<div class='card'><div class='card-label'>{$e($profile['label'] ?? $key)}</div><div class='card-sub'>{$e($profile['description'] ?? '')}</div><div class='card-sub'>wake {$e($values['internal_wake_batch'] ?? '')} · request {$e($values['request_drain_batch'] ?? '')} · inbox {$e($values['inbox_drain_batch'] ?? '')}</div><div class='card-sub'>fallback {$e($values['wake_fallback_batch'] ?? '')}×{$e($values['wake_fallback_cycles'] ?? '')} · connect {$e($values['delivery_connect_timeout'] ?? '')}s · total {$e($values['delivery_timeout'] ?? '')}s</div></div>";
        }
        $input = static function (string $name, array $tuning, $default = '') use ($e): string {
            return "<input type='number' min='1' name='{$e($name)}' value='{$e($tuning[$name] ?? $default)}' style='width:110px'>";
        };

        $batchCount24h = (int)($batchStats['count_24h'] ?? 0);
        $slowBatches24h = (int)($batchStats['slow_24h'] ?? 0);
        $avgBatch24h = number_format((float)($batchStats['avg_duration_s'] ?? 0), 3, '.', '');
        $p95Batch24h = number_format((float)($batchStats['p95_duration_s'] ?? 0), 3, '.', '');
        $maxBatch24h = number_format((float)($batchStats['max_duration_s'] ?? 0), 3, '.', '');

        return <<<HTML
<div class="cards" style="margin-bottom:1.5rem">
  <div class="card"><div class="card-label">Pending (not sent)</div><div class="card-value" style="color:{$pendingColor}">{$stats['pending']}</div></div>
  <div class="card"><div class="card-label">Retrying (≥1 failure)</div><div class="card-value" style="color:{$retryingColor}">{$stats['retrying']}</div></div>
  <div class="card"><div class="card-label">Due for delivery</div><div class="card-value" style="color:{$dueColor}">{$stats['due']}</div><div class="card-sub">next: {$nextDueLabel}</div></div>
  <div class="card"><div class="card-label">Permanent failures</div><div class="card-value" style="color:{$failedColor}">{$stats['failed']}</div><div class="card-sub">last attempt: {$lastAttemptLabel}</div></div>
  <div class="card"><div class="card-label">Total queued</div><div class="card-value">{$stats['total']}</div><div class="card-sub">resolved in 24h: {$stats['resolved_recent']}</div></div>
</div>

<div class="cards" style="margin-bottom:1.5rem">
  <div class="card"><div class="card-label">Failures by type</div>{$bucketHtml}</div>
  <div class="card"><div class="card-label">Top queued servers</div>{$domainHtml}</div>
</div>

<div class="cards" style="margin-bottom:1.5rem">
  <div class="card"><div class="card-label">Batch runs (24h)</div><div class="card-value">{$batchCount24h}</div></div>
  <div class="card"><div class="card-label">Slow batches (≥5s)</div><div class="card-value" style="color:var(--amber)">{$slowBatches24h}</div></div>
  <div class="card"><div class="card-label">Average batch</div><div class="card-value">{$avgBatch24h}s</div><div class="card-sub">p95: {$p95Batch24h}s</div></div>
  <div class="card"><div class="card-label">Worst batch (24h)</div><div class="card-value">{$maxBatch24h}s</div></div>
</div>

<div class="section" style="margin-bottom:1.5rem">
  <div class="section-title">Recent batch summaries</div>
  <div style="font-size:.72rem;color:var(--text3);margin-bottom:.8rem">
    A quick health view of recent queue runs. These are the same batch-level signals that used to be useful mainly in the server log.
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>When</th><th>Batch</th><th>Work</th><th>Results</th><th>Due remaining</th><th>Duration</th></tr></thead>
      <tbody>{$batchRows}</tbody>
    </table>
  </div>
</div>

<div class="section">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.6rem;margin-bottom:1rem">
    <div class="section-title" style="margin:0">Queued deliveries (latest 200)</div>
    <div style="display:flex;gap:.5rem;flex-wrap:wrap">
      <form method="POST" action="/admin/delivery-queue">
        <input type="hidden" name="action" value="retry_all">
        <button class="btn btn-primary btn-sm">↻ Retry all now</button>
      </form>
      <form method="POST" action="/admin/delivery-queue">
        <input type="hidden" name="action" value="clear_failed">
        <button class="btn btn-ghost btn-sm">Remove failed (≥8)</button>
      </form>
      <form method="POST" action="/admin/delivery-queue" onsubmit="return confirm('Delete the entire queue?')">
        <input type="hidden" name="action" value="clear_all">
        <button class="btn btn-danger btn-sm">Clear all</button>
      </form>
    </div>
  </div>
  <div style="font-size:.72rem;color:var(--text3);margin-bottom:.8rem">
    Deliveries are processed automatically by the app's internal wake-up mechanism and at the end of ActivityPub requests. "Retry all now" moves scheduled deliveries to immediate execution. The system distinguishes transient failures better (DNS, network, 429, some 401s) from terminal failures (for example 404/410/403 or rejected payloads).
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Destination server</th><th>Activity</th><th>Status</th><th>Latest result</th><th>Next attempt</th><th>Last attempt</th><th>Created</th></tr></thead>
      <tbody>{$tableRows}</tbody>
    </table>
  </div>
</div>

<div class="section" style="margin-top:1.5rem">
  <div class="section-title">Latest recorded attempts</div>
  <div style="font-size:.72rem;color:var(--text3);margin-bottom:.8rem">
    Recent history of attempted deliveries, including successes and failures resolved later. Useful for separating transient issues from persistent errors.
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Destination server</th><th>Activity</th><th>Result</th><th>Detail</th><th>When</th></tr></thead>
      <tbody>{$attemptRows}</tbody>
    </table>
  </div>
</div>

<div class="section" style="margin-top:1.5rem">
  <div class="section-title">Delivery queue tuning</div>
  <div style="font-size:.72rem;color:var(--text3);margin-bottom:.8rem">
    Review the queue first, then change these values if you need to tune behaviour for your hosting. Choose a profile first, and only override individual values if you need a custom setup.
  </div>
  <form method="POST" action="/admin/delivery-queue">
    <input type="hidden" name="action" value="save_tuning">
    <div class="form-row">
      <div class="form-group" style="min-width:280px">
        <label>Server profile</label>
        <select name="preset">{$profileOptions}</select>
      </div>
    </div>
    <div class="cards" style="margin:.4rem 0 1rem 0">{$profileCards}</div>
    <div class="form-row">
      <div class="form-group"><label>Internal wake batch</label>{$input('internal_wake_batch', $tuning, 10)}</div>
      <div class="form-group"><label>Request drain batch</label>{$input('request_drain_batch', $tuning, 1)}</div>
      <div class="form-group"><label>Inbox drain batch</label>{$input('inbox_drain_batch', $tuning, 3)}</div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Wake fallback batch</label>{$input('wake_fallback_batch', $tuning, 6)}</div>
      <div class="form-group"><label>Wake fallback cycles</label>{$input('wake_fallback_cycles', $tuning, 1)}</div>
      <div class="form-group"><label>Connect timeout (seconds)</label>{$input('delivery_connect_timeout', $tuning, 3)}</div>
      <div class="form-group"><label>Total timeout (seconds)</label>{$input('delivery_timeout', $tuning, 6)}</div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>&nbsp;</label>
        <button class="btn btn-primary" type="submit">Save tuning</button>
      </div>
    </div>
  </form>
</div>
HTML;
    }

    // ── Login page ────────────────────────────────────────────

    private function loginPage(string $csrf, string $error): string
    {
        $e      = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $errHtml= $error ? "<div class='flash flash-error'>{$e($error)}</div>" : '';
        $domain = $e(AP_DOMAIN);
        return <<<HTML
<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — {$domain}</title>
<link rel="icon" href="{$e(\site_favicon_url())}">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#fff;--surface:#fff;--hover:#F3F3F8;--blue:#0085FF;--blue2:#0070E0;--blue-bg:#E0EDFF;--border:#E5E7EB;--text:#0F1419;--text2:#66788A;--text3:#8D99A5;--red:#EC4040}
@media(prefers-color-scheme:dark){:root{--bg:#0A0E14;--surface:#161823;--hover:#1E2030;--border:#2E3039;--text:#F1F3F5;--text2:#7B8794;--text3:#545864;--blue-bg:#0C1B3A}}
body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
nav{background:color-mix(in srgb,var(--surface) 85%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:.75rem 1.5rem;display:flex;align-items:center;gap:.5rem;position:fixed;top:0;left:0;right:0;z-index:10}
nav .fedi-symbol{font-size:1.4rem;color:var(--blue);line-height:1}
nav .logo{font-size:1rem;font-weight:800;color:var(--blue);text-decoration:none}
.wrap{width:100%;max-width:400px;margin-top:3rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:2rem}
.card-title{font-size:.75rem;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.07em;margin-bottom:1.5rem}
.field{margin-bottom:1rem}
.field label{display:block;font-size:.8rem;font-weight:600;color:var(--text2);margin-bottom:.4rem}
.field input{width:100%;padding:.65rem .9rem;background:var(--surface);border:1px solid var(--border);border-radius:9999px;color:var(--text);font-size:.95rem;outline:none;transition:border .15s,box-shadow .15s;font-family:inherit}
.field input:focus{border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-bg)}
.flash{padding:.65rem 1rem;border-radius:8px;font-size:.85rem;border-left:3px solid;margin-bottom:1.2rem;background:color-mix(in srgb,var(--red) 8%,var(--surface));border-color:var(--red);color:var(--red)}
.submit{width:100%;margin-top:1.4rem;padding:.75rem;background:var(--blue);border:none;border-radius:9999px;color:#fff;font-size:.95rem;font-weight:700;cursor:pointer;transition:background .15s;font-family:inherit}
.submit:hover{background:var(--blue2)}
.hero{text-align:center;margin-bottom:2rem}
.hero h1{font-size:1.5rem;font-weight:800;letter-spacing:-.03em;margin-bottom:.3rem}
.hero p{color:var(--text2);font-size:.9rem}
</style></head>
<body>
<nav><span class="fedi-symbol">⋰⋱</span><a class="logo" href="/">Starling</a></nav>
<div class="wrap">
  <div class="hero">
    <h1>Administration panel</h1>
    <p>Restricted to administrators</p>
  </div>
  <div class="card">
    <div class="card-title">Sign in</div>
    {$errHtml}
    <form method="POST" action="/admin/login">
      <input type="hidden" name="csrf" value="{$e($csrf)}">
      <div class="field"><label>Username</label><input type="text" name="username" required autofocus autocomplete="username" placeholder="username"></div>
      <div class="field"><label>Password</label><input type="password" name="password" required autocomplete="current-password" placeholder="••••••••"></div>
      <button class="submit" type="submit">Sign in to admin</button>
    </form>
  </div>
</div>
</body></html>
HTML;
    }

    // ── Paginador ─────────────────────────────────────────────

    private function paginator(int $page, int $pages, string $base): string
    {
        if ($pages <= 1) return '';
        $sep  = str_contains($base, '?') ? '&' : '?';
        $html = '<div class="pagination">';
        if ($page > 1)      $html .= "<a href='{$base}{$sep}page=" . ($page-1) . "' class='page-btn'>← Previous</a>";
        $start = max(1, $page - 2); $end = min($pages, $page + 2);
        for ($i = $start; $i <= $end; $i++) {
            $cls   = $i === $page ? ' current' : '';
            $html .= "<a href='{$base}{$sep}page=$i' class='page-btn$cls'>$i</a>";
        }
        if ($page < $pages) $html .= "<a href='{$base}{$sep}page=" . ($page+1) . "' class='page-btn'>Next →</a>";
        $html .= "<span class='page-info'>Page $page of $pages</span></div>";
        return $html;
    }
}
