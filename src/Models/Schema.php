<?php
declare(strict_types=1);

namespace App\Models;

class Schema
{
    private static bool $done = false;

    /** Increment this when adding new tables or columns. */
    public const SCHEMA_VERSION = 20;

    public static function install(): void
    {
        if (self::$done) return;
        self::$done = true;

        $db = DB::pdo();
        $currentVersion = (int)$db->query('PRAGMA user_version')->fetchColumn();

        self::ensureCriticalBackfillsNow($db, $currentVersion);

        // Skip all DDL if the schema is already at the current version.
        // On the very first run (user_version=0) this falls through and creates everything.
        if ($currentVersion >= self::SCHEMA_VERSION) return;

        $db->exec("CREATE TABLE IF NOT EXISTS users (
            id              TEXT PRIMARY KEY,
            username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password        TEXT NOT NULL,
            display_name    TEXT NOT NULL DEFAULT '',
            bio             TEXT NOT NULL DEFAULT '',
            avatar          TEXT NOT NULL DEFAULT '',
            header          TEXT NOT NULL DEFAULT '',
            is_admin        INTEGER NOT NULL DEFAULT 0,
            is_locked       INTEGER NOT NULL DEFAULT 0,
            is_bot          INTEGER NOT NULL DEFAULT 0,
            is_suspended    INTEGER NOT NULL DEFAULT 0,
            follower_count  INTEGER NOT NULL DEFAULT 0,
            following_count INTEGER NOT NULL DEFAULT 0,
            status_count    INTEGER NOT NULL DEFAULT 0,
            private_key     TEXT NOT NULL DEFAULT '',
            public_key      TEXT NOT NULL DEFAULT '',
            -- Account mobility: alsoKnownAs = old AP URLs this account moved from
            also_known_as   TEXT NOT NULL DEFAULT '[]',
            -- Account mobility: moved_to = AP URL of new account (set on outgoing Move)
            moved_to        TEXT NOT NULL DEFAULT '',
            -- Preferences stored as JSON
            preferences     TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )");

        // Migrate existing users table (ADD COLUMN is idempotent via try/catch)
        foreach (['also_known_as TEXT NOT NULL DEFAULT \'[]\'',
                  'moved_to TEXT NOT NULL DEFAULT \'\'',
                  'preferences TEXT NOT NULL DEFAULT \'{}\'',
                  'fields TEXT NOT NULL DEFAULT \'[]\'',
                  'discoverable INTEGER NOT NULL DEFAULT 1',
                  'indexable INTEGER NOT NULL DEFAULT 1'] as $col) {
            try { $db->exec("ALTER TABLE users ADD COLUMN $col"); } catch (\Throwable) {}
        }

        $db->exec("CREATE TABLE IF NOT EXISTS oauth_apps (
            id            TEXT PRIMARY KEY,
            owner_user_id TEXT NOT NULL DEFAULT '',
            name          TEXT NOT NULL,
            website       TEXT NOT NULL DEFAULT '',
            redirect_uri  TEXT NOT NULL,
            client_id     TEXT NOT NULL UNIQUE,
            client_secret TEXT NOT NULL,
            scopes        TEXT NOT NULL DEFAULT 'read write follow push',
            created_at    TEXT NOT NULL
        )");
        try { $db->exec("ALTER TABLE oauth_apps ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}

        $db->exec("CREATE TABLE IF NOT EXISTS oauth_codes (
            code              TEXT PRIMARY KEY,
            app_id            TEXT NOT NULL,
            user_id           TEXT NOT NULL,
            scopes            TEXT NOT NULL,
            redirect_uri      TEXT NOT NULL,
            code_challenge    TEXT NOT NULL DEFAULT '',
            challenge_method  TEXT NOT NULL DEFAULT '',
            expires_at        TEXT NOT NULL,
            created_at        TEXT NOT NULL
        )");

        // Migrate oauth_codes for PKCE
        foreach (['code_challenge TEXT NOT NULL DEFAULT \'\'',
                  'challenge_method TEXT NOT NULL DEFAULT \'\''] as $col) {
            try { $db->exec("ALTER TABLE oauth_codes ADD COLUMN $col"); } catch (\Throwable) {}
        }

        $db->exec("CREATE TABLE IF NOT EXISTS oauth_tokens (
            token      TEXT PRIMARY KEY,
            app_id     TEXT NOT NULL,
            user_id    TEXT NOT NULL,
            scopes     TEXT NOT NULL,
            last_used  TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )");

        try { $db->exec("ALTER TABLE oauth_tokens ADD COLUMN last_used TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE statuses ADD COLUMN quote_of_id TEXT"); } catch (\Throwable) {}
        // Idempotency-Key support: prevents duplicate posts when the Mastodon iOS app retries
        // a failed status creation request. The key is per-user (same key from different users
        // is allowed). Index allows fast lookup without full table scan.
        try { $db->exec("ALTER TABLE statuses ADD COLUMN idempotency_key TEXT"); } catch (\Throwable) {}
        try { $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_status_idempotency ON statuses(user_id, idempotency_key) WHERE idempotency_key IS NOT NULL"); } catch (\Throwable) {}

        $db->exec("CREATE TABLE IF NOT EXISTS statuses (
            id               TEXT PRIMARY KEY,
            uri              TEXT NOT NULL UNIQUE,
            user_id          TEXT NOT NULL,
            reply_to_id      TEXT,
            reply_to_uid     TEXT,
            reblog_of_id     TEXT,
            quote_of_id      TEXT,
            content          TEXT NOT NULL DEFAULT '',
            cw               TEXT NOT NULL DEFAULT '',
            visibility       TEXT NOT NULL DEFAULT 'public',
            language         TEXT NOT NULL DEFAULT 'pt',
            sensitive        INTEGER NOT NULL DEFAULT 0,
            local            INTEGER NOT NULL DEFAULT 1,
            reply_count      INTEGER NOT NULL DEFAULT 0,
            reblog_count     INTEGER NOT NULL DEFAULT 0,
            favourite_count  INTEGER NOT NULL DEFAULT 0,
            expires_at       TEXT,
            created_at       TEXT NOT NULL,
            updated_at       TEXT NOT NULL
        )");
        try { $db->exec("ALTER TABLE statuses ADD COLUMN expires_at TEXT"); } catch (\Throwable) {}

        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_user ON statuses(user_id,created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_pub  ON statuses(visibility,local,created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_uri  ON statuses(uri)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_expires ON statuses(expires_at)");

        // Link preview cards (cache de Open Graph)
        $db->exec("CREATE TABLE IF NOT EXISTS link_cards (
            url         TEXT PRIMARY KEY,
            title       TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            image       TEXT NOT NULL DEFAULT '',
            provider    TEXT NOT NULL DEFAULT '',
            card_type   TEXT NOT NULL DEFAULT 'link',
            share_count INTEGER NOT NULL DEFAULT 0,
            fetched_at  TEXT NOT NULL
        )");
        // Migrate existing link_cards table
        try { $db->exec("ALTER TABLE link_cards ADD COLUMN share_count INTEGER NOT NULL DEFAULT 0"); } catch (\Throwable) {}

        $db->exec("CREATE TABLE IF NOT EXISTS follows (
            id           TEXT PRIMARY KEY,
            follower_id  TEXT NOT NULL,
            following_id TEXT NOT NULL,
            pending      INTEGER NOT NULL DEFAULT 0,
            local        INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT NOT NULL,
            UNIQUE(follower_id, following_id)
        )");

        $db->exec("CREATE INDEX IF NOT EXISTS idx_follows_fwer  ON follows(follower_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_follows_fwing ON follows(following_id)");

        try { $db->exec("ALTER TABLE follows ADD COLUMN notify INTEGER NOT NULL DEFAULT 0"); } catch (\Throwable) {}

        $db->exec("CREATE TABLE IF NOT EXISTS favourites (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            status_id  TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, status_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS reblogs (
            id               TEXT PRIMARY KEY,
            user_id          TEXT NOT NULL,
            status_id        TEXT NOT NULL,
            reblog_status_id TEXT NOT NULL,
            created_at       TEXT NOT NULL,
            UNIQUE(user_id, status_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS bookmarks (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            status_id  TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, status_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS notifications (
            id           TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL,
            from_acct_id TEXT NOT NULL,
            type         TEXT NOT NULL,
            status_id    TEXT,
            read_at      TEXT,
            created_at   TEXT NOT NULL
        )");

        $db->exec("CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id,created_at DESC)");

        $db->exec("CREATE TABLE IF NOT EXISTS remote_actors (
            id              TEXT PRIMARY KEY,
            masto_id        TEXT NOT NULL DEFAULT '',
            username        TEXT NOT NULL,
            domain          TEXT NOT NULL,
            display_name    TEXT NOT NULL DEFAULT '',
            bio             TEXT NOT NULL DEFAULT '',
            avatar          TEXT NOT NULL DEFAULT '',
            header_img      TEXT NOT NULL DEFAULT '',
            public_key      TEXT NOT NULL DEFAULT '',
            inbox_url       TEXT NOT NULL DEFAULT '',
            shared_inbox    TEXT NOT NULL DEFAULT '',
            outbox_url      TEXT NOT NULL DEFAULT '',
            followers_url   TEXT NOT NULL DEFAULT '',
            following_url   TEXT NOT NULL DEFAULT '',
            also_known_as   TEXT NOT NULL DEFAULT '[]',
            moved_to        TEXT NOT NULL DEFAULT '',
            is_locked       INTEGER NOT NULL DEFAULT 0,
            is_bot          INTEGER NOT NULL DEFAULT 0,
            follower_count  INTEGER NOT NULL DEFAULT 0,
            following_count INTEGER NOT NULL DEFAULT 0,
            status_count    INTEGER NOT NULL DEFAULT 0,
            raw_json        TEXT NOT NULL DEFAULT '{}',
            fetched_at      TEXT NOT NULL,
            UNIQUE(username,domain)
        )");

        foreach (['also_known_as TEXT NOT NULL DEFAULT \'[]\'',
                  'moved_to TEXT NOT NULL DEFAULT \'\'',
                  'published_at TEXT',
                  'fields TEXT NOT NULL DEFAULT \'[]\'',
                  'url TEXT NOT NULL DEFAULT \'\'',
        ] as $col) {
            try { $db->exec("ALTER TABLE remote_actors ADD COLUMN $col"); } catch (\Throwable) {}
        }

        $db->exec("CREATE INDEX IF NOT EXISTS idx_remote_masto_id ON remote_actors(masto_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_remote_domain  ON remote_actors(domain)");

        // Backfill masto_id for remote actors that were inserted before it was computed
        // (rows with masto_id='' get md5(id) computed in PHP since SQLite has no md5())
        $stale = $db->query("SELECT id FROM remote_actors WHERE masto_id='' LIMIT 200")->fetchAll(\PDO::FETCH_ASSOC);
        foreach ($stale as $row) {
            $st = $db->prepare("UPDATE remote_actors SET masto_id=? WHERE id=?");
            $st->execute([md5($row['id']), $row['id']]);
        }

        $db->exec("CREATE TABLE IF NOT EXISTS media_attachments (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            status_id   TEXT,
            type        TEXT NOT NULL DEFAULT 'image',
            url         TEXT NOT NULL,
            preview_url TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            blurhash    TEXT NOT NULL DEFAULT '',
            width       INTEGER,
            height      INTEGER,
            created_at  TEXT NOT NULL
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS status_media (
            status_id TEXT NOT NULL,
            media_id  TEXT NOT NULL,
            position  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(status_id,media_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS hashtags (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
            created_at TEXT NOT NULL
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS status_hashtags (
            status_id  TEXT NOT NULL,
            hashtag_id TEXT NOT NULL,
            PRIMARY KEY(status_id,hashtag_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS blocks (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            target_id  TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id,target_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS mutes (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            target_id  TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id,target_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS lists (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            title      TEXT NOT NULL,
            created_at TEXT NOT NULL
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS list_accounts (
            list_id    TEXT NOT NULL,
            account_id TEXT NOT NULL,
            PRIMARY KEY(list_id,account_id)
        )");

        // Migrate list_accounts: rows stored with masto_id (md5) instead of AP URL
        // Fix: resolve each masto_id to the real remote_actors.id (AP URL)
        $staleListAccounts = $db->query(
            "SELECT list_id, account_id FROM list_accounts
             WHERE account_id NOT LIKE '%-%'
               AND LENGTH(account_id)=32
               AND account_id NOT IN (SELECT id FROM users)"
        )->fetchAll(\PDO::FETCH_ASSOC);
        foreach ($staleListAccounts as $row) {
            $st = $db->prepare("SELECT id FROM remote_actors WHERE masto_id=?");
            $st->execute([$row['account_id']]);
            $ra = $st->fetch(\PDO::FETCH_ASSOC);
            if ($ra && $ra['id'] !== $row['account_id']) {
                // Replace masto_id with AP URL; ignore conflict if already migrated
                $ins = $db->prepare("INSERT OR IGNORE INTO list_accounts(list_id,account_id) VALUES(?,?)");
                $ins->execute([$row['list_id'], $ra['id']]);
                $del = $db->prepare("DELETE FROM list_accounts WHERE list_id=? AND account_id=?");
                $del->execute([$row['list_id'], $row['account_id']]);
            }
        }

        // Pinned statuses
        $db->exec("CREATE TABLE IF NOT EXISTS status_pins (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            status_id  TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, status_id)
        )");

        // Endorsed accounts (profile pins) and per-account private notes
        $db->exec("CREATE TABLE IF NOT EXISTS account_endorsements (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            target_id  TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, target_id)
        )");
        $db->exec("CREATE TABLE IF NOT EXISTS account_notes (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            target_id  TEXT NOT NULL,
            comment    TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, target_id)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_account_endorsements_user ON account_endorsements(user_id, created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_account_notes_user ON account_notes(user_id, updated_at DESC)");

        // Status edit history
        $db->exec("CREATE TABLE IF NOT EXISTS status_edits (
            id         TEXT PRIMARY KEY,
            status_id  TEXT NOT NULL,
            content    TEXT NOT NULL DEFAULT '',
            cw         TEXT NOT NULL DEFAULT '',
            sensitive  INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_edits_status ON status_edits(status_id, created_at DESC)");

        // Polls
        $db->exec("CREATE TABLE IF NOT EXISTS polls (
            id           TEXT PRIMARY KEY,
            status_id    TEXT NOT NULL UNIQUE,
            multiple     INTEGER NOT NULL DEFAULT 0,
            hide_totals  INTEGER NOT NULL DEFAULT 0,
            expires_at   TEXT,
            closed_at    TEXT,
            votes_count  INTEGER NOT NULL DEFAULT 0,
            voters_count INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        )");
        $db->exec("CREATE TABLE IF NOT EXISTS poll_options (
            id          TEXT PRIMARY KEY,
            poll_id     TEXT NOT NULL,
            title       TEXT NOT NULL,
            position    INTEGER NOT NULL,
            votes_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE(poll_id, position)
        )");
        $db->exec("CREATE TABLE IF NOT EXISTS poll_votes (
            id         TEXT PRIMARY KEY,
            poll_id    TEXT NOT NULL,
            option_id  TEXT NOT NULL,
            user_id    TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(poll_id, user_id, option_id)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_polls_status ON polls(status_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_poll_options_poll ON poll_options(poll_id, position)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_poll_votes_poll_user ON poll_votes(poll_id, user_id)");

        // Timeline markers (save reading position)
        $db->exec("CREATE TABLE IF NOT EXISTS markers (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            timeline    TEXT NOT NULL,
            last_read_id TEXT NOT NULL,
            version     INTEGER NOT NULL DEFAULT 0,
            updated_at  TEXT NOT NULL,
            UNIQUE(user_id, timeline)
        )");

        // Content filters
        $db->exec("CREATE TABLE IF NOT EXISTS filters (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            title       TEXT NOT NULL,
            context     TEXT NOT NULL DEFAULT '[]',
            action      TEXT NOT NULL DEFAULT 'warn',
            expires_at  TEXT,
            created_at  TEXT NOT NULL
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS filter_keywords (
            id         TEXT PRIMARY KEY,
            filter_id  TEXT NOT NULL,
            keyword    TEXT NOT NULL,
            whole_word INTEGER NOT NULL DEFAULT 0
        )");

        // User-level domain blocks
        $db->exec("CREATE TABLE IF NOT EXISTS user_domain_blocks (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            domain     TEXT NOT NULL COLLATE NOCASE,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, domain)
        )");

        // Admin-level domain blocks
        $db->exec("CREATE TABLE IF NOT EXISTS domain_blocks (
            id         TEXT PRIMARY KEY,
            domain     TEXT NOT NULL UNIQUE COLLATE NOCASE,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS inbox_log (
            id         TEXT PRIMARY KEY,
            actor_url  TEXT NOT NULL,
            type       TEXT NOT NULL,
            raw_json   TEXT NOT NULL,
            error      TEXT NOT NULL DEFAULT '',
            sig_headers TEXT NOT NULL DEFAULT '{}',
            sig_debug  TEXT NOT NULL DEFAULT '{}',
            request_method TEXT NOT NULL DEFAULT '',
            request_path TEXT NOT NULL DEFAULT '',
            request_host TEXT NOT NULL DEFAULT '',
            remote_ip  TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )");
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN sig_headers TEXT NOT NULL DEFAULT '{}'"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN sig_debug TEXT NOT NULL DEFAULT '{}'"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN request_method TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN request_path TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN request_host TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN remote_ip TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}

        // Featured tags (shown on profile)
        $db->exec("CREATE TABLE IF NOT EXISTS featured_tags (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            name       TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, name)
        )");

        // Follow suggestions seed
        $db->exec("CREATE TABLE IF NOT EXISTS follow_suggestions (
            id         TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            source     TEXT NOT NULL DEFAULT 'past_interactions',
            created_at TEXT NOT NULL
        )");

        // Hashtag follows (user subscribes to a tag)
        $db->exec("CREATE TABLE IF NOT EXISTS tag_follows (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            hashtag_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, hashtag_id)
        )");

        // Additional indexes for frequent query patterns (added in schema v2)
        $db->exec("CREATE INDEX IF NOT EXISTS idx_media_user        ON media_attachments(user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_link_cards_trend  ON link_cards(fetched_at DESC, share_count DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_reblogs_status    ON reblogs(status_id, user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_favs_status       ON favourites(status_id, user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_sh_hashtag        ON status_hashtags(hashtag_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_notif_user_id     ON notifications(user_id, id DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_reply_to  ON statuses(reply_to_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_quote_of  ON statuses(quote_of_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_notif_status     ON notifications(status_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_trends_base ON statuses(visibility, reblog_of_id, created_at DESC, id DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_status_reblog_lookup ON statuses(reblog_of_id, visibility, created_at DESC)");

        // Federated delivery queue — created centrally here so it can have proper indexes.
        // Delivery.php::ensureQueueTable() is kept for backwards compatibility but is now a no-op
        // on installations that ran this schema migration first.
        $db->exec("CREATE TABLE IF NOT EXISTS delivery_queue (
            id            TEXT PRIMARY KEY,
            actor_id      TEXT NOT NULL,
            inbox_url     TEXT NOT NULL,
            payload       TEXT NOT NULL,
            payload_hash  TEXT NOT NULL DEFAULT '',
            attempts      INTEGER NOT NULL DEFAULT 1,
            next_retry_at TEXT NOT NULL,
            created_at    TEXT NOT NULL,
            last_http_code INTEGER NOT NULL DEFAULT 0,
            last_error    TEXT NOT NULL DEFAULT '',
            last_error_bucket TEXT NOT NULL DEFAULT '',
            last_error_detail TEXT NOT NULL DEFAULT '',
            last_attempt_at TEXT NOT NULL DEFAULT '',
            last_response_body TEXT NOT NULL DEFAULT '',
            processing_until TEXT NOT NULL DEFAULT ''
        )");
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN payload_hash TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN last_http_code INTEGER NOT NULL DEFAULT 0"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN last_error TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN last_error_bucket TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN last_error_detail TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN last_response_body TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE delivery_queue ADD COLUMN processing_until TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_dq_dedupe ON delivery_queue(actor_id, inbox_url, payload_hash)"); } catch (\Throwable) {}
        $db->exec("CREATE INDEX IF NOT EXISTS idx_dq_retry ON delivery_queue(next_retry_at, attempts)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_dq_ready ON delivery_queue(next_retry_at, processing_until, attempts)");

        // ActivityPub relay subscriptions
        $db->exec("CREATE TABLE IF NOT EXISTS relay_subscriptions (
            id          TEXT    PRIMARY KEY,
            actor_url   TEXT    NOT NULL UNIQUE,
            inbox_url   TEXT    NOT NULL DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'pending',
            receive_posts INTEGER NOT NULL DEFAULT 1,
            daily_limit INTEGER NOT NULL DEFAULT 500,
            created_at  TEXT    NOT NULL
        )");
        try { $db->exec("ALTER TABLE relay_subscriptions ADD COLUMN receive_posts INTEGER NOT NULL DEFAULT 1"); } catch (\Throwable) {}

        // Lists: position column for user-defined ordering
        try { $db->exec("ALTER TABLE lists ADD COLUMN position INTEGER NOT NULL DEFAULT 0"); } catch (\Throwable) {}

        // Tombstones: track deleted posts so we can return 410 Gone (AP spec compliance)
        $db->exec("CREATE TABLE IF NOT EXISTS tombstones (
            uri        TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'public',
            deleted_at TEXT NOT NULL
        )");
        try { $db->exec("ALTER TABLE tombstones ADD COLUMN user_id TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE tombstones ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'"); } catch (\Throwable) {}

        // Admin action audit trail
        $db->exec("CREATE TABLE IF NOT EXISTS admin_action_log (
            id            TEXT PRIMARY KEY,
            admin_user_id TEXT NOT NULL DEFAULT '',
            action        TEXT NOT NULL,
            target_type   TEXT NOT NULL DEFAULT '',
            target_id     TEXT NOT NULL DEFAULT '',
            summary       TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at    TEXT NOT NULL
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_admin_action_log_created ON admin_action_log(created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_admin_action_log_admin ON admin_action_log(admin_user_id, created_at DESC)");

        // Moderation / report tracking
        $db->exec("CREATE TABLE IF NOT EXISTS admin_reports (
            id                TEXT PRIMARY KEY,
            reporter_id       TEXT NOT NULL DEFAULT '',
            target_kind       TEXT NOT NULL DEFAULT 'account',
            target_id         TEXT NOT NULL DEFAULT '',
            target_label      TEXT NOT NULL DEFAULT '',
            reason            TEXT NOT NULL DEFAULT '',
            comment           TEXT NOT NULL DEFAULT '',
            status            TEXT NOT NULL DEFAULT 'open',
            moderation_action TEXT NOT NULL DEFAULT '',
            resolution_note   TEXT NOT NULL DEFAULT '',
            handled_by        TEXT NOT NULL DEFAULT '',
            handled_at        TEXT NOT NULL DEFAULT '',
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_admin_reports_status_created ON admin_reports(status, created_at DESC)");

        // Instance-managed content pages and structured rules
        $db->exec("CREATE TABLE IF NOT EXISTS instance_content (
            content_key TEXT PRIMARY KEY,
            title       TEXT NOT NULL DEFAULT '',
            body        TEXT NOT NULL DEFAULT '',
            format      TEXT NOT NULL DEFAULT 'text',
            updated_by  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL
        )");

        // Mark schema as fully installed at this version.
        $db->exec('PRAGMA user_version = ' . self::SCHEMA_VERSION);
    }

    public static function ensureCriticalBackfillsNow(?\PDO $db = null, ?int $currentVersion = null): void
    {
        $db ??= DB::pdo();
        $currentVersion ??= (int)$db->query('PRAGMA user_version')->fetchColumn();
        if ($currentVersion < self::SCHEMA_VERSION || !self::criticalBackfillsMarked() || !self::criticalBackfillsPresent($db)) {
            self::ensureCriticalBackfills($db);
            self::markCriticalBackfills();
        }
    }

    private static function ensureCriticalBackfills(\PDO $db): void
    {
        try { $db->exec("ALTER TABLE statuses ADD COLUMN quote_of_id TEXT"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE statuses ADD COLUMN idempotency_key TEXT"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE statuses ADD COLUMN expires_at TEXT"); } catch (\Throwable) {}
        try { $db->exec("CREATE TABLE IF NOT EXISTS tombstones (
            uri TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'public',
            deleted_at TEXT NOT NULL
        )"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE tombstones ADD COLUMN user_id TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE tombstones ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN sig_headers TEXT NOT NULL DEFAULT '{}'"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN sig_debug TEXT NOT NULL DEFAULT '{}'"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN request_method TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN request_path TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN request_host TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("ALTER TABLE inbox_log ADD COLUMN remote_ip TEXT NOT NULL DEFAULT ''"); } catch (\Throwable) {}
        try { $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_status_idempotency ON statuses(user_id, idempotency_key) WHERE idempotency_key IS NOT NULL"); } catch (\Throwable) {}
        try { $db->exec("CREATE INDEX IF NOT EXISTS idx_status_expires ON statuses(expires_at)"); } catch (\Throwable) {}
    }

    private static function criticalBackfillsMarkerPath(): string
    {
        $dir = ROOT . '/storage/runtime';
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        return $dir . '/schema_backfills_v' . self::SCHEMA_VERSION . '.lock';
    }

    private static function criticalBackfillsMarked(): bool
    {
        return is_file(self::criticalBackfillsMarkerPath());
    }

    private static function criticalBackfillsPresent(\PDO $db): bool
    {
        $hasColumn = static function (string $table, string $column) use ($db): bool {
            try {
                $rows = $db->query('PRAGMA table_info(' . $table . ')')->fetchAll(\PDO::FETCH_ASSOC) ?: [];
            } catch (\Throwable) {
                return false;
            }
            foreach ($rows as $row) {
                if (($row['name'] ?? null) === $column) return true;
            }
            return false;
        };

        if (!$hasColumn('statuses', 'idempotency_key')) return false;
        if (!$hasColumn('statuses', 'quote_of_id')) return false;
        if (!$hasColumn('statuses', 'expires_at')) return false;
        return true;
    }

    private static function markCriticalBackfills(): void
    {
        @file_put_contents(self::criticalBackfillsMarkerPath(), now_iso(), LOCK_EX);
    }
}
