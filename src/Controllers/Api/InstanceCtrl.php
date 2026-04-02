<?php
declare(strict_types=1);

namespace App\Controllers\Api;

use App\Models\{DB, UserModel, AdminModel};

class InstanceCtrl
{
    private function mastodonVersionLabel(): string
    {
        return '4.2.0-compatible+' . AP_SOFTWARE . '-' . AP_VERSION;
    }

    private function activeLoginCountBetween(string $from, string $to): int
    {
        return (int)(DB::one(
            "SELECT COUNT(DISTINCT user_id) c
             FROM oauth_tokens
             WHERE user_id != ''
               AND COALESCE(NULLIF(last_used, ''), created_at) >= ?
               AND COALESCE(NULLIF(last_used, ''), created_at) < ?",
            [$from, $to]
        )['c'] ?? 0);
    }

    public function v1(array $p): void
    {
        json_out($this->base());
    }

    public function v2(array $p): void
    {
        $b = $this->base();
        $contact = self::adminAccount();
        $iconUrl = $contact['avatar_static'] ?? $contact['avatar'] ?? null;
        $out = [
            'uri'         => AP_DOMAIN,
            'domain'      => AP_DOMAIN,
            'title'       => AP_NAME,
            'version'     => $this->mastodonVersionLabel(),
            'source_url'  => AP_SOURCE_URL,
            'description' => AP_DESCRIPTION,
            'usage'       => ['users' => ['active_month' => (int)(DB::one(
                "SELECT COUNT(DISTINCT user_id) c FROM statuses
                 WHERE local=1 AND created_at>?
                   AND user_id NOT IN (SELECT id FROM users WHERE is_suspended=1)
                   AND (expires_at IS NULL OR expires_at='' OR expires_at>?)",
                [gmdate('Y-m-d\TH:i:s\Z', strtotime('-30 days')), now_iso()]
            )['c'] ?? 0)]],
            'icon'        => $iconUrl ? [['src' => $iconUrl, 'size' => '192x192']] : [],
            'languages'   => ['en'],
            'api_versions' => ['mastodon' => 6],
            'configuration' => array_merge($b['configuration'], [
                'accounts'    => ['max_featured_tags' => 10, 'max_pinned_statuses' => 20],
                'translation' => ['enabled' => false],
                'starling' => [
                    'hosting' => 'shared-host-php',
                    'push' => ['supported' => false],
                    'streaming' => ['sse' => true, 'websocket' => false],
                ],
            ]),
            'registrations'   => ['enabled' => AP_OPEN_REG, 'approval_required' => false, 'message' => null, 'min_age' => null, 'reason_required' => false],
            'contact'         => ['email' => AP_ADMIN_EMAIL, 'account' => $contact],
            'rules'           => $b['rules'],
            'urls'            => ['streaming' => AP_BASE_URL . '/api/v1/streaming'],
        ];
        if ($iconUrl) {
            $out['thumbnail'] = ['url' => $iconUrl, 'blurhash' => null, 'versions' => null];
        }
        json_out($out);
    }

    public function peers(array $p): void
    {
        $rows = DB::all('SELECT DISTINCT domain FROM remote_actors WHERE domain != ? ORDER BY domain ASC LIMIT 500', [AP_DOMAIN]);
        json_out(array_column($rows, 'domain'));
    }

    public function activity(array $p): void
    {
        // Weekly activity for the past 12 weeks
        $out = [];
        for ($i = 11; $i >= 0; $i--) {
            $week_end   = gmdate('Y-m-d\TH:i:s\Z', strtotime("-{$i} weeks"));
            $week_start = gmdate('Y-m-d\TH:i:s\Z', strtotime("-" . ($i + 1) . " weeks"));
            $logins  = $this->activeLoginCountBetween($week_start, $week_end);
            $reg     = DB::count('users', 'created_at>=? AND created_at<?', [$week_start, $week_end]);
            $posts   = (int)(DB::one(
                "SELECT COUNT(*) c FROM statuses
                 WHERE local=1 AND created_at>=? AND created_at<?
                   AND user_id NOT IN (SELECT id FROM users WHERE is_suspended=1)
                   AND (expires_at IS NULL OR expires_at='' OR expires_at>?)",
                [$week_start, $week_end, now_iso()]
            )['c'] ?? 0);
            $out[]   = [
                'week'      => (string)strtotime($week_start),
                'statuses'  => (string)$posts,
                'logins'    => (string)$logins,
                'registrations' => (string)$reg,
            ];
        }
        json_out($out);
    }
    public function emojis(array $p): void   { json_out([]); }
    public function rules(array $p): void    { json_out(AdminModel::instanceRules()); }

    private static function adminAccount(): ?array
    {
        $admin = DB::one('SELECT * FROM users WHERE is_admin=1 AND is_suspended=0 ORDER BY created_at ASC LIMIT 1');
        return $admin ? UserModel::toMasto($admin) : null;
    }

    private function base(): array
    {
        $rules = AdminModel::instanceRules();
        $privacy = AdminModel::instanceContent('privacy');
        $terms = AdminModel::instanceContent('terms');
        return [
            'uri'               => AP_DOMAIN,
            'title'             => AP_NAME,
            'short_description' => AP_DESCRIPTION,
            'description'       => AP_DESCRIPTION,
            'email'             => AP_ADMIN_EMAIL,
            'version'           => $this->mastodonVersionLabel(),
            'urls'              => ['streaming_api' => AP_BASE_URL . '/api/v1/streaming'],
            'stats'             => [
                'user_count'   => DB::count('users', 'is_suspended=0'),
                'status_count' => (int)(DB::one(
                    "SELECT COUNT(*) c FROM statuses
                     WHERE local=1
                       AND user_id NOT IN (SELECT id FROM users WHERE is_suspended=1)
                       AND (expires_at IS NULL OR expires_at='' OR expires_at>?)",
                    [now_iso()]
                )['c'] ?? 0),
                'domain_count' => (int)(DB::one('SELECT COUNT(DISTINCT domain) n FROM remote_actors WHERE domain != ?', [AP_DOMAIN])['n'] ?? 0),
            ],
            'languages'          => ['en'],
            'contact_account'    => self::adminAccount(),
            'vapid_key'          => '',
            'rules'              => $rules,
            'registrations'      => AP_OPEN_REG,
            'approval_required'  => false,
            'invites_enabled'    => false,
            'configuration' => [
                'statuses' => [
                    'max_characters'              => AP_POST_CHARS,
                    'max_media_attachments'       => 4,
                    'characters_reserved_per_url' => 23,
                ],
                'media_attachments' => [
                    'supported_mime_types' => ['image/jpeg','image/png','image/gif','image/webp','image/avif','image/heic','image/heif','video/mp4','video/webm','video/quicktime'],
                    'image_size_limit'     => AP_MAX_UPLOAD_MB * 1024 * 1024,
                    'video_size_limit'     => AP_MAX_UPLOAD_MB * 1024 * 1024,
                    'description_limit'    => 1500,
                    'image_matrix_limit'   => 16777216,
                    'video_frame_rate_limit' => 60,
                    'video_matrix_limit'   => 2304000,
                ],
                'polls'    => ['max_options' => 4, 'max_characters_per_option' => 50, 'min_expiration' => 300, 'max_expiration' => 2629746],
                'accounts' => [
                    'max_featured_tags' => 10,
                    'max_pinned_statuses' => 20,
                    'max_profile_fields' => 4,
                    'profile_field_name_limit' => 255,
                    'profile_field_value_limit' => 255,
                ],
                'urls'     => [
                    'streaming' => AP_BASE_URL . '/api/v1/streaming',
                    'status' => null,
                    'about' => AP_BASE_URL . '/about',
                    'privacy_policy' => trim((string)($privacy['body'] ?? '')) !== '' ? AP_BASE_URL . '/privacy' : null,
                    'terms_of_service' => trim((string)($terms['body'] ?? '')) !== '' ? AP_BASE_URL . '/terms' : null,
                ],
                'vapid'    => ['public_key' => ''],
                'quotes'      => ['enabled' => true],
                'limited_federation' => false,
                'sso_enabled' => false,
                'starling' => [
                    'hosting' => 'shared-host-php',
                    'push' => ['supported' => false],
                    'streaming' => ['sse' => true, 'websocket' => false],
                ],
            ],
        ];
    }
}
