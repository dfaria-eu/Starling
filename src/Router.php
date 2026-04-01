<?php
declare(strict_types=1);

namespace App;

class Router
{
    /** @var array<array{method:string,regex:string,keys:string[],handler:string}> */
    private array $routes = [];

    public function __construct()
    {
        // ── Well-known / federation discovery ────────────────
        $this->get('/.well-known/webfinger',          'WellKnown@webfinger');
        $this->get('/.well-known/nodeinfo',           'WellKnown@nodeinfo');
        $this->get('/.well-known/host-meta',          'WellKnown@hostMeta');
        $this->get('/nodeinfo/2.0',                   'WellKnown@nodeinfoDoc');
        $this->get('/.well-known/atproto-did',        'WellKnown@atprotoDid');

        // ── ActivityPub actor ─────────────────────────────────
        $this->get('/users',                          'ActorCtrl@index');
        $this->get('/users/',                         'ActorCtrl@index');
        $this->get('/users/:username',                'ActorCtrl@show');
        $this->get('/users/:username/followers',      'ActorCtrl@followers');
        $this->get('/users/:username/following',      'ActorCtrl@following');
        $this->get('/users/:username/outbox',         'ActorCtrl@outbox');
        $this->get('/users/:username/featured',       'ActorCtrl@featured');
        $this->post('/users/:username/inbox',         'ActorCtrl@inbox');

        // ── ActivityPub objects / tags ────────────────────────
        $this->get('/objects/:id',                    'NoteCtrl@show');
        $this->get('/tags/:tag',                      'TagCtrl@show');

        // ── Shared inbox ──────────────────────────────────────
        $this->post('/inbox',                         'SharedInboxCtrl@handle');

        // ── OAuth ─────────────────────────────────────────────
        $this->post('/api/v1/apps',                   'Api\AppsCtrl@create');
        $this->get('/api/v1/apps/verify_credentials', 'Api\AppsCtrl@verifyCredentials');
        $this->get('/oauth/authorize',                'Api\OAuthCtrl@authorizeForm');
        $this->post('/oauth/authorize',               'Api\OAuthCtrl@authorizeSubmit');
        $this->post('/oauth/token',                   'Api\OAuthCtrl@token');
        $this->post('/oauth/revoke',                  'Api\OAuthCtrl@revoke');

        // ── Instance ──────────────────────────────────────────
        $this->get('/api/v1/instance',                'Api\InstanceCtrl@v1');
        $this->get('/api/v2/instance',                'Api\InstanceCtrl@v2');
        $this->get('/api/v1/instance/peers',          'Api\InstanceCtrl@peers');
        $this->get('/api/v1/instance/activity',       'Api\InstanceCtrl@activity');
        $this->get('/api/v1/instance/rules',          'Api\InstanceCtrl@rules');
        $this->get('/api/v1/custom_emojis',           'Api\InstanceCtrl@emojis');

        // ── Accounts ──────────────────────────────────────────
        $this->post('/api/v1/accounts',                      'Api\AccountsCtrl@register');
        $this->get('/api/v1/accounts/verify_credentials',    'Api\AccountsCtrl@verifyCredentials');
        $this->patch('/api/v1/accounts/update_credentials',  'Api\AccountsCtrl@updateCredentials');
        $this->get('/api/v1/accounts/relationships',         'Api\AccountsCtrl@relationships');
        $this->get('/api/v1/accounts/search',                'Api\AccountsCtrl@search');
        $this->get('/api/v1/accounts/lookup',                'Api\AccountsCtrl@lookup');
        $this->get('/api/v1/accounts/familiar_followers',    'Api\AccountsCtrl@familiarFollowers');
        // ── Account mobility (Move) — deve ficar antes de /:id ─
        $this->get('/api/v1/accounts/aliases',               'Api\MigrationCtrl@listAliases');
        $this->post('/api/v1/accounts/aliases',              'Api\MigrationCtrl@addAlias');
        $this->delete('/api/v1/accounts/aliases/:acct',      'Api\MigrationCtrl@removeAlias');
        $this->post('/api/v1/accounts/move',                 'Api\MigrationCtrl@move');
        $this->get('/api/v1/accounts/:id',                   'Api\AccountsCtrl@show');
        $this->get('/api/v1/accounts/:id/statuses',          'Api\AccountsCtrl@statuses');
        $this->get('/api/v1/accounts/:id/followers',         'Api\AccountsCtrl@followers');
        $this->get('/api/v1/accounts/:id/following',         'Api\AccountsCtrl@following');
        $this->get('/api/v1/accounts/:id/lists',             'Api\AccountsCtrl@accountLists');
        $this->post('/api/v1/accounts/:id/follow',           'Api\AccountsCtrl@follow');
        $this->post('/api/v1/accounts/:id/unfollow',         'Api\AccountsCtrl@unfollow');
        $this->post('/api/v1/accounts/:id/block',            'Api\AccountsCtrl@block');
        $this->post('/api/v1/accounts/:id/unblock',          'Api\AccountsCtrl@unblock');
        $this->post('/api/v1/accounts/:id/mute',             'Api\AccountsCtrl@mute');
        $this->post('/api/v1/accounts/:id/unmute',           'Api\AccountsCtrl@unmute');
        $this->post('/api/v1/accounts/:id/pin',              'Api\AccountsCtrl@pinAccount');
        $this->post('/api/v1/accounts/:id/unpin',            'Api\AccountsCtrl@unpinAccount');
        $this->post('/api/v1/accounts/:id/note',             'Api\AccountsCtrl@noteAccount');

        // ── Statuses ──────────────────────────────────────────
        $this->post('/api/v1/statuses',                      'Api\StatusesCtrl@create');
        $this->get('/api/v1/statuses/:id',                   'Api\StatusesCtrl@show');
        $this->delete('/api/v1/statuses/:id',                'Api\StatusesCtrl@delete');
        $this->put('/api/v1/statuses/:id',                   'Api\StatusesCtrl@edit');
        $this->patch('/api/v1/statuses/:id',                 'Api\StatusesCtrl@edit');
        $this->get('/api/v1/statuses/:id/context',           'Api\StatusesCtrl@context');
        $this->get('/api/v1/statuses/:id/reblogged_by',      'Api\StatusesCtrl@rebloggedBy');
        $this->get('/api/v1/statuses/:id/favourited_by',     'Api\StatusesCtrl@favouritedBy');
        $this->post('/api/v1/statuses/:id/reblog',           'Api\StatusesCtrl@reblog');
        $this->post('/api/v1/statuses/:id/unreblog',         'Api\StatusesCtrl@unreblog');
        $this->post('/api/v1/statuses/:id/favourite',        'Api\StatusesCtrl@favourite');
        $this->post('/api/v1/statuses/:id/unfavourite',      'Api\StatusesCtrl@unfavourite');
        $this->post('/api/v1/statuses/:id/bookmark',         'Api\StatusesCtrl@bookmark');
        $this->post('/api/v1/statuses/:id/unbookmark',       'Api\StatusesCtrl@unbookmark');
        $this->post('/api/v1/statuses/:id/pin',              'Api\PinsCtrl@pin');
        $this->post('/api/v1/statuses/:id/unpin',            'Api\PinsCtrl@unpin');
        $this->get('/api/v1/statuses/:id/card',              'Api\StatusesCtrl@card');
        $this->get('/api/v1/statuses/:id/history',           'Api\StatusHistoryCtrl@history');
        $this->get('/api/v1/statuses/:id/source',            'Api\StatusHistoryCtrl@source');
        $this->get('/api/v1/polls/:id',                      'Api\PollsCtrl@show');
        $this->post('/api/v1/polls/:id/votes',               'Api\PollsCtrl@vote');

        // ── Timelines ─────────────────────────────────────────
        $this->get('/api/v1/timelines/home',          'Api\TimelinesCtrl@home');
        $this->get('/api/v1/timelines/public',        'Api\TimelinesCtrl@public');
        $this->get('/api/v1/timelines/tag/:hashtag',  'Api\TimelinesCtrl@tag');
        $this->get('/api/v1/timelines/list/:id',      'Api\TimelinesCtrl@listTimeline');

        // ── Notifications ─────────────────────────────────────
        $this->get('/api/v2/notifications',                  'Api\NotificationsCtrl@indexV2');
        $this->get('/api/v1/notifications',                  'Api\NotificationsCtrl@index');
        // Specific sub-routes MUST come before /:id to avoid being captured as id='policy' etc.
        $this->get('/api/v1/notifications/policy',           'Api\NotificationsCtrl@policy');
        $this->put('/api/v1/notifications/policy',           'Api\NotificationsCtrl@policy');
        $this->get('/api/v1/notifications/requests',         'Api\NotificationsCtrl@requests');
        $this->post('/api/v1/notifications/clear',           'Api\NotificationsCtrl@clear');
        $this->get('/api/v1/notifications/:id',              'Api\NotificationsCtrl@show');
        $this->post('/api/v1/notifications/:id/dismiss',     'Api\NotificationsCtrl@dismiss');

        // ── Search ────────────────────────────────────────────
        $this->get('/api/v1/search',                  'Api\SearchCtrl@index');
        $this->get('/api/v2/search',                  'Api\SearchCtrl@index');

        // ── Media (serve ficheiros gravados) ──────────────────
        $this->get('/media/:filename',                'Api\MediaCtrl@serve');

        // ── Media API ─────────────────────────────────────────
        $this->post('/api/v1/media',                  'Api\MediaCtrl@upload');
        $this->post('/api/v2/media',                  'Api\MediaCtrl@upload');
        $this->get('/api/v1/media/:id',               'Api\MediaCtrl@show');
        $this->put('/api/v1/media/:id',               'Api\MediaCtrl@update');
        $this->patch('/api/v1/media/:id',             'Api\MediaCtrl@update');
        $this->get('/api/v2/media/:id',               'Api\MediaCtrl@show');
        $this->put('/api/v2/media/:id',               'Api\MediaCtrl@update');
        $this->patch('/api/v2/media/:id',             'Api\MediaCtrl@update');

        // ── Trends (v1 + v2 aliases) ──────────────────────────
        $this->get('/api/v1/trends',                  'Api\TrendsCtrl@tags');
        $this->get('/api/v1/trends/tags',             'Api\TrendsCtrl@tags');
        $this->get('/api/v1/trends/statuses',         'Api\TrendsCtrl@statuses');
        $this->get('/api/v1/trends/links',            'Api\TrendsCtrl@links');
        $this->get('/api/v1/trends/people',           'Api\TrendsCtrl@people');
        $this->get('/api/v2/trends',                  'Api\TrendsCtrl@tags');
        $this->get('/api/v2/trends/tags',             'Api\TrendsCtrl@tags');
        $this->get('/api/v2/trends/statuses',         'Api\TrendsCtrl@statuses');
        $this->get('/api/v2/trends/links',            'Api\TrendsCtrl@links');

        // ── Misc lists ────────────────────────────────────────
        $this->get('/api/v1/bookmarks',               'Api\BookmarksCtrl@index');
        $this->get('/api/v1/favourites',              'Api\FavouritesCtrl@index');
        $this->get('/api/v1/blocks',                  'Api\BlocksCtrl@index');
        $this->get('/api/v1/mutes',                   'Api\MutesCtrl@index');
        $this->get('/api/v1/conversations',           'Api\ConversationsCtrl@index');
        $this->post('/api/v1/conversations/:id/read', 'Api\\ConversationsCtrl@read');
        $this->get('/api/v1/follow_requests',         'Api\FollowRequestsCtrl@index');
        $this->post('/api/v1/follow_requests/:id/authorize', 'Api\FollowRequestsCtrl@authorize');
        $this->post('/api/v1/follow_requests/:id/reject',    'Api\FollowRequestsCtrl@reject');

        // ── Preferences ───────────────────────────────────────
        $this->get('/api/v1/preferences',             'Api\PreferencesCtrl@show');
        $this->get('/api/v1/sessions',                'Api\SessionsCtrl@index');
        $this->delete('/api/v1/sessions',             'Api\SessionsCtrl@delete');
        $this->delete('/api/v1/sessions/:id',         'Api\SessionsCtrl@delete');
        $this->get('/api/v1/developer/apps',          'Api\DeveloperAppsCtrl@index');
        $this->post('/api/v1/developer/apps',         'Api\DeveloperAppsCtrl@create');
        $this->delete('/api/v1/developer/apps/:id',   'Api\DeveloperAppsCtrl@delete');
        $this->post('/api/v1/developer/apps/:id/tokens','Api\DeveloperAppsCtrl@createToken');
        $this->delete('/api/v1/developer/tokens/:token','Api\DeveloperAppsCtrl@revokeToken');
        $this->get('/api/v1/follows/export',          'Api\FollowsCsvCtrl@export');
        $this->delete('/api/v1/account',              'Api\AccountLifecycleCtrl@delete');

        // ── Markers (timeline position) ───────────────────────
        $this->get('/api/v1/markers',                 'Api\MarkersCtrl@show');
        $this->post('/api/v1/markers',                'Api\MarkersCtrl@update');

        // ── Announcements ─────────────────────────────────────
        $this->get('/api/v1/announcements',           'Api\AnnouncementsCtrl@index');

        // ── Filters ───────────────────────────────────────────
        $this->get('/api/v1/filters',                 'Api\FiltersCtrl@index');
        $this->post('/api/v1/filters',                'Api\FiltersCtrl@create');
        $this->get('/api/v1/filters/:id',             'Api\FiltersCtrl@show');
        $this->put('/api/v1/filters/:id',             'Api\FiltersCtrl@update');
        $this->delete('/api/v1/filters/:id',          'Api\FiltersCtrl@delete');
        // v2 filters (same implementation)
        $this->get('/api/v2/filters',                 'Api\FiltersCtrl@index');
        $this->post('/api/v2/filters',                'Api\FiltersCtrl@create');
        $this->get('/api/v2/filters/:id',             'Api\FiltersCtrl@show');
        $this->put('/api/v2/filters/:id',             'Api\FiltersCtrl@update');
        $this->delete('/api/v2/filters/:id',          'Api\FiltersCtrl@delete');

        // Domain blocks (user-level)
        $this->get('/api/v1/domain_blocks',           'Api\UserDomainBlocksCtrl@index');
        $this->post('/api/v1/domain_blocks',          'Api\UserDomainBlocksCtrl@create');
        $this->delete('/api/v1/domain_blocks',        'Api\UserDomainBlocksCtrl@delete');

        // Follow suggestions
        $this->get('/api/v1/follow_suggestions',      'Api\SuggestionsCtrl@indexV1');
        $this->delete('/api/v1/follow_suggestions/:id','Api\SuggestionsCtrl@delete');
        $this->get('/api/v2/suggestions',             'Api\SuggestionsCtrl@index');
        $this->delete('/api/v2/suggestions/:id',      'Api\SuggestionsCtrl@delete');

        // Featured tags
        $this->get('/api/v1/featured_tags/suggestions',  'Api\FeaturedTagsSuggestionsCtrl@index');
        $this->get('/api/v1/featured_tags',              'Api\FeaturedTagsCtrl@index');
        $this->post('/api/v1/featured_tags',             'Api\FeaturedTagsCtrl@create');
        $this->delete('/api/v1/featured_tags/:id',       'Api\FeaturedTagsCtrl@delete');
        $this->get('/api/v1/accounts/:id/featured_tags', 'Api\AccountFeaturedTagsCtrl@show');

        // ── Lists ─────────────────────────────────────────────
        $this->get('/api/v1/lists',                   'Api\ListsCtrl@index');
        $this->post('/api/v1/lists',                  'Api\ListsCtrl@create');
        $this->post('/api/v1/lists/reorder',          'Api\ListsCtrl@reorder');
        $this->get('/api/v1/lists/:id',               'Api\ListsCtrl@show');
        $this->put('/api/v1/lists/:id',               'Api\ListsCtrl@update');
        $this->delete('/api/v1/lists/:id',            'Api\ListsCtrl@delete');
        $this->get('/api/v1/lists/:id/accounts',      'Api\ListsCtrl@accounts');
        $this->post('/api/v1/lists/:id/accounts',     'Api\ListsCtrl@addAccounts');
        $this->delete('/api/v1/lists/:id/accounts',   'Api\ListsCtrl@removeAccounts');

        // ── Push (stub) ───────────────────────────────────────
        $this->get('/api/v1/push/subscription',       'Api\\PushCtrl@show');
        $this->post('/api/v1/push/subscription',      'Api\\PushCtrl@create');
        $this->delete('/api/v1/push/subscription',    'Api\\PushCtrl@delete');

        // ── Hashtag follow API ────────────────────────────────
        $this->get('/api/v1/tags/:name',              'Api\TagsApiCtrl@show');
        $this->post('/api/v1/tags/:name/follow',      'Api\TagsApiCtrl@follow');
        $this->post('/api/v1/tags/:name/unfollow',    'Api\TagsApiCtrl@unfollow');

        // Followed tags (Elk usa isto na inicialização)
        $this->get('/api/v1/followed_tags',           'Api\\MiscCtrl@followedTags');

        // Streaming SSE (eventos em tempo real)
        $this->get('/api/v1/streaming/health',        'Api\\MiscCtrl@streamingHealth');
        $this->get('/api/v1/streaming',               'Api\\MiscCtrl@stream');
        $this->get('/api/v1/streaming/user',          'Api\\MiscCtrl@stream');
        $this->get('/api/v1/streaming/public',        'Api\\MiscCtrl@stream');
        $this->get('/api/v1/streaming/public/local',  'Api\\MiscCtrl@stream');
        $this->get('/api/v1/streaming/public/media',  'Api\\MiscCtrl@stream');
        $this->get('/api/v1/streaming/public/local/media', 'Api\\MiscCtrl@stream');

        // ── Admin ─────────────────────────────────────────────
        $this->get('/admin/login',                    'AdminCtrl@login');
        $this->post('/admin/login',                   'AdminCtrl@login');
        $this->post('/admin/logout',                  'AdminCtrl@logout');
        $this->get('/admin',                          'AdminCtrl@dashboard');
        $this->get('/admin/users',                    'AdminCtrl@users');
        $this->post('/admin/users/create',            'AdminCtrl@createUser');
        $this->post('/admin/users/:id/update',        'AdminCtrl@updateUser');
        $this->post('/admin/users/:id/:action',       'AdminCtrl@userAction');
        $this->get('/admin/action-log',               'AdminCtrl@actionLog');
        $this->get('/admin/media',                    'AdminCtrl@media');
        $this->post('/admin/media/:id/delete',        'AdminCtrl@mediaDelete');
        $this->get('/admin/content',                  'AdminCtrl@content');
        $this->post('/admin/content',                 'AdminCtrl@contentSave');
        $this->get('/admin/reports',                  'AdminCtrl@reports');
        $this->post('/admin/reports/create',          'AdminCtrl@reportCreate');
        $this->post('/admin/reports/:id/update',      'AdminCtrl@reportUpdate');
        $this->get('/admin/federation',               'AdminCtrl@federation');
        $this->post('/admin/federation',              'AdminCtrl@federationAction');
        $this->get('/admin/settings',                 'AdminCtrl@settings');
        $this->post('/admin/settings',                'AdminCtrl@settingsSave');
        $this->get('/admin/relays',                   'AdminCtrl@relays');
        $this->post('/admin/relays/action',           'AdminCtrl@relayAction');
        $this->get('/admin/inbox-log',                'AdminCtrl@inboxLog');
        $this->get('/admin/inbox-log/:id',            'AdminCtrl@inboxLogDetail');
        $this->get('/admin/maintenance',              'AdminCtrl@maintenance');
        $this->post('/admin/maintenance',             'AdminCtrl@maintenanceAction');
        $this->get('/admin/delivery-queue',           'AdminCtrl@deliveryQueue');
        $this->post('/admin/delivery-queue',          'AdminCtrl@deliveryQueueAction');

        // ── Web Client ────────────────────────────────────────────────────────
        $this->get('/web/login',              'WebClientCtrl@login');
        $this->post('/web/login',             'WebClientCtrl@login');
        $this->get('/web/register',           'WebClientCtrl@register');
        $this->post('/web/register',          'WebClientCtrl@register');
        $this->post('/web/logout',            'WebClientCtrl@logout');
        $this->post('/web/admin-sso',         'WebClientCtrl@adminSso');
        $this->get('/web',                    'WebClientCtrl@home');
        $this->get('/web/local',              'WebClientCtrl@local');
        $this->get('/web/notifications',      'WebClientCtrl@notifications');
        $this->get('/web/search',             'WebClientCtrl@search');
        $this->get('/web/thread/:id',         'WebClientCtrl@thread');
        $this->get('/web/profile/:id',        'WebClientCtrl@profile');
        $this->get('/web/favourites',         'WebClientCtrl@favourites');
        $this->get('/web/bookmarks',          'WebClientCtrl@bookmarks');
        $this->get('/web/explore',            'WebClientCtrl@explore');
        $this->get('/web/conversations',      'WebClientCtrl@conversations');
        $this->get('/web/lists',              'WebClientCtrl@lists');
        $this->get('/web/list/:id',           'WebClientCtrl@listTimeline');
        $this->get('/web/edit-profile',       'WebClientCtrl@editProfile');
        $this->get('/web/settings',           'WebClientCtrl@settings');
        $this->get('/web/compose',            'WebClientCtrl@intentCompose');

        // ── Web UI ────────────────────────────────────────────
        $this->get('/',           'WebCtrl@home');
        $this->get('/about',      'WebCtrl@about');
        $this->get('/privacy',    'WebCtrl@privacy');
        $this->get('/terms',      'WebCtrl@terms');
        $this->get('/rules',      'WebCtrl@rules');
        $this->get('/@:username',     'WebCtrl@profile');
        $this->get('/@:username/',    'WebCtrl@profile');
        $this->get('/@:username/:id', 'WebCtrl@status');
        $this->get('/install', 'WebCtrl@install');
        $this->post('/install','WebCtrl@installPost');
        $this->post('/internal/queue-wake', 'InternalCtrl@queueWake');
    }

    // ── Route registration shortcuts ──────────────────────────

    private function get(string $p, string $h): void    { $this->add('GET',    $p, $h); }
    private function post(string $p, string $h): void   { $this->add('POST',   $p, $h); }
    private function put(string $p, string $h): void    { $this->add('PUT',    $p, $h); }
    private function patch(string $p, string $h): void  { $this->add('PATCH',  $p, $h); }
    private function delete(string $p, string $h): void { $this->add('DELETE', $p, $h); }

    private function add(string $method, string $pattern, string $handler): void
    {
        $keys  = [];
        $regex = preg_replace_callback('/:([\w]+)/', function ($m) use (&$keys) {
            $keys[] = $m[1];
            return '([^/]+)';
        }, $pattern);
        $this->routes[] = [
            'method'  => $method,
            'regex'   => '#^' . $regex . '$#',
            'keys'    => $keys,
            'handler' => $handler,
        ];
    }

    // ── Dispatch ──────────────────────────────────────────────

    public function dispatch(): void
    {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if ($method === 'HEAD') $method = 'GET';

        // CORS preflight
        if ($method === 'OPTIONS') {
            http_response_code(204);
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Authorization, Content-Type, Idempotency-Key');
            header('Access-Control-Expose-Headers: Link, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset');
            header('Access-Control-Max-Age: 86400');
            exit;
        }

        // Support X-HTTP-Method-Override (used by some Mastodon clients)
        if ($method === 'POST' && !empty($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $method = strtoupper($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
        }

        $uri = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/');

        foreach ($this->routes as $route) {
            if ($route['method'] !== $method) continue;
            if (!preg_match($route['regex'], $uri, $matches)) continue;

            $params = [];
            foreach ($route['keys'] as $i => $key) {
                $params[$key] = $matches[$i + 1];
            }

            $this->invoke($route['handler'], $params);
            return;
        }

        err_out('Not Found', 404);
    }

    private function invoke(string $handler, array $params): void
    {
        [$cls, $method] = explode('@', $handler, 2);

        $fqcn = 'App\\Controllers\\' . str_replace('/', '\\', $cls);

        if (!class_exists($fqcn)) {
            err_out("Controller $fqcn not found", 500);
        }
        $obj = new $fqcn();
        if (!method_exists($obj, $method)) {
            err_out("Method $method not found on $fqcn", 500);
        }
        $obj->$method($params);
    }
}
