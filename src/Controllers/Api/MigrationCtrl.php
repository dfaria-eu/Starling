<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, RemoteActorModel};
use App\ActivityPub\{Builder, Delivery};

/**
 * Account Mobility (Mastodon-compatible)
 *
 * Incoming move (another server → this server):
 *   - Remote server sends Move{actor: old, object: new} to followers' inboxes
 *   - InboxProcessor::onMove() handles this: migrates follows
 *
 * Outgoing move (this server → another server):
 *   POST /api/v1/accounts/move
 *     { acct: "new@other.server", current_password: "..." }
 *   Steps:
 *     1. Verify new account has alsoKnownAs pointing back at us
 *     2. Mark local account as moved (moved_to)
 *     3. Federate Move activity to all followers
 *
 * Alias management (prerequisite for incoming move):
 *   POST /api/v1/accounts/aliases        { acct: "old@other.server" }
 *   DELETE /api/v1/accounts/aliases/:acct
 *   GET  /api/v1/accounts/aliases
 */
class MigrationCtrl
{
    // ── Aliases (alsoKnownAs) ─────────────────────────────────

    public function listAliases(array $p): void
    {
        $user = require_auth('read');
        $aka  = json_decode($user['also_known_as'] ?? '[]', true) ?: [];
        $out  = [];
        foreach ($aka as $url) {
            if (!is_string($url) || $url === '') continue;
            $pathUser = ltrim(rawurldecode(basename(parse_url($url, PHP_URL_PATH) ?? '')), '@');
            $local = $pathUser !== '' ? DB::one('SELECT * FROM users WHERE username=?', [$pathUser]) : null;
            if ($local && in_array($url, [actor_url($local['username']), ap_url('@' . $local['username'])], true)) {
                $out[] = UserModel::toMasto($local, $user['id']);
                continue;
            }
            $ra = DB::one('SELECT * FROM remote_actors WHERE id=?', [$url]) ?? RemoteActorModel::fetch($url);
            if ($ra) $out[] = UserModel::remoteToMasto($ra);
        }
        json_out($out);
    }

    public function addAlias(array $p): void
    {
        $user = require_auth(['write', 'write:accounts']);
        $d    = req_body();
        $acct = trim($d['acct'] ?? '');
        if (!$acct) err_out('acct required', 422);

        $acct = ltrim($acct, '@');
        if (!str_contains($acct, '@')) err_out('Must be a remote account (user@domain)', 422);

        [$username, $domain] = explode('@', $acct, 2);
        if (!$username || !$domain) err_out('Invalid account format (user@domain)', 422);
        if (is_local($domain)) err_out('Cannot alias a local account', 422);

        // Fetch remote actor to get their AP URL
        $ra = RemoteActorModel::fetchByAcct($username, $domain);
        if (!$ra) err_out('Remote account not found', 422);

        $apUrl = $ra['id'];
        $aka   = json_decode($user['also_known_as'] ?? '[]', true) ?: [];

        if (!in_array($apUrl, $aka, true)) {
            $aka[] = $apUrl;
            DB::update('users', ['also_known_as' => json_encode($aka)], 'id=?', [$user['id']]);

            // Federate the actor update so followers know — queued
            $updated = UserModel::byId($user['id']);
            Delivery::queueToFollowers($updated, Builder::updateActor($updated));
        }

        json_out(UserModel::remoteToMasto($ra));
    }

    public function removeAlias(array $p): void
    {
        $user  = require_auth(['write', 'write:accounts']);
        $acct  = urldecode($p['acct'] ?? '');
        $aka   = json_decode($user['also_known_as'] ?? '[]', true) ?: [];

        // Accept both AP URL and acct format (user@domain).
        // Use exact equality only — str_ends_with() would match "user@example.com"
        // against "otheruser@example.com", incorrectly removing unrelated aliases.
        $aka = array_values(array_filter($aka, function ($url) use ($acct) {
            if ($url === $acct) return false;
            $parsed    = parse_url($url);
            $pathSegments = explode('/', trim($parsed['path'] ?? '', '/'));
            $localAcct = ltrim((string)end($pathSegments), '@') . '@' . ($parsed['host'] ?? '');
            return $localAcct !== $acct;
        }));

        DB::update('users', ['also_known_as' => json_encode($aka)], 'id=?', [$user['id']]);

        $updated = UserModel::byId($user['id']);
        Delivery::queueToFollowers($updated, Builder::updateActor($updated));

        json_out([]);
    }

    // ── Move ──────────────────────────────────────────────────

    public function move(array $p): void
    {
        $user = require_auth(['write', 'write:accounts']);
        $d    = req_body();

        // Require current password confirmation
        if (!password_verify($d['current_password'] ?? '', $user['password'])) {
            err_out('Invalid password', 422);
        }

        $newAcct = trim($d['acct'] ?? '');
        if (!$newAcct) err_out('acct required', 422);

        $newAcct = ltrim($newAcct, '@');
        if (!str_contains($newAcct, '@')) err_out('Must be a remote account (user@domain)', 422);

        [$newUsername, $newDomain] = explode('@', $newAcct, 2);
        if (!$newUsername || !$newDomain) err_out('Invalid account format (user@domain)', 422);
        if (is_local($newDomain)) err_out('Cannot move to a local account', 422);

        // Fetch new account
        $newActor = RemoteActorModel::fetchByAcct($newUsername, $newDomain);
        if (!$newActor) err_out('New account not found or unreachable', 422);

        // CRITICAL: verify new account lists us in alsoKnownAs
        $theirAka = json_decode($newActor['also_known_as'] ?? '[]', true) ?: [];
        $ourUrl   = actor_url($user['username']);
        if (!in_array($ourUrl, $theirAka, true)) {
            err_out(
                'New account has not listed this account as an alias. ' .
                'Add ' . $ourUrl . ' to alsoKnownAs on ' . $newDomain . ' first.',
                422
            );
        }

        // Mark as moved
        DB::update('users', [
            'moved_to'   => $newActor['id'],
            'updated_at' => now_iso(),
        ], 'id=?', [$user['id']]);

        // Federate Move + actor Update — queued for async delivery
        $moveActivity = Builder::move($user, $newActor['id']);
        $updated = UserModel::byId($user['id']);
        Delivery::queueToFollowers($user, $moveActivity);
        Delivery::queueToFollowers($updated, Builder::updateActor($updated));

        json_out(UserModel::toMasto($updated));
    }
}
