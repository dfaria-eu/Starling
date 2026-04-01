<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Models\{DB, UserModel};

class WellKnown
{
    public function webfinger(array $p): void
    {
        $res = $_GET['resource'] ?? '';

        if (str_starts_with($res, 'acct:')) {
            $acctPart = substr($res, 5);
            // Strip leading @
            $acctPart = ltrim($acctPart, '@');
            [$user, $domain] = array_pad(explode('@', $acctPart, 2), 2, '');
        } elseif (preg_match('~/users/([^/?#]+)~', $res, $m)) {
            $user   = $m[1];
            $domain = parse_url($res, PHP_URL_HOST) ?? '';
        } elseif (preg_match('~/@([^/?#@]+)~', $res, $m)) {
            // https://domain/@username format
            $user   = $m[1];
            $domain = parse_url($res, PHP_URL_HOST) ?? '';
        } else {
            err_out('Invalid resource', 400);
        }

        if (!is_local($domain)) err_out('Not found', 404);

        $u = UserModel::byUsername($user);
        if (!$u) err_out('Not found', 404);

        $url = actor_url($u['username']);
        $htmlUrl = ap_url('@' . $u['username']);
        json_out([
            'subject' => 'acct:' . $u['username'] . '@' . AP_DOMAIN,
            'aliases' => [$url, $htmlUrl],
            'links'   => [
                ['rel' => 'http://webfinger.net/rel/profile-page', 'type' => 'text/html',                 'href' => $htmlUrl],
                ['rel' => 'self',                                   'type' => 'application/activity+json', 'href' => $url],
            ],
        ], 200, 'application/jrd+json');
    }

    public function nodeinfo(array $p): void
    {
        json_out(['links' => [
            ['rel' => 'http://nodeinfo.diaspora.software/ns/schema/2.0', 'href' => ap_url('nodeinfo/2.0')],
        ]]);
    }

    public function nodeinfoDoc(array $p): void
    {
        $users      = DB::count('users', 'is_suspended=0');
        $posts      = DB::count('statuses', 'local=1');
        $month      = gmdate('Y-m-d\TH:i:s\Z', strtotime('-30 days'));
        $halfyear   = gmdate('Y-m-d\TH:i:s\Z', strtotime('-180 days'));
        $active     = (int)(DB::one('SELECT COUNT(DISTINCT user_id) c FROM statuses WHERE local=1 AND created_at>?', [$month])['c'] ?? 0);
        $activeHalf = (int)(DB::one('SELECT COUNT(DISTINCT user_id) c FROM statuses WHERE local=1 AND created_at>?', [$halfyear])['c'] ?? 0);

        json_out([
            'version'  => '2.0',
            'software' => ['name' => AP_SOFTWARE, 'version' => AP_VERSION],
            'protocols'=> ['activitypub'],
            'services' => ['inbound' => [], 'outbound' => []],
            'usage'    => [
                'users' => ['total' => $users, 'activeMonth' => $active, 'activeHalfyear' => $activeHalf],
                'localPosts' => $posts,
            ],
            'openRegistrations' => AP_OPEN_REG,
            'metadata' => ['nodeName' => AP_NAME, 'nodeDescription' => AP_DESCRIPTION],
        ]);
    }

    public function hostMeta(array $p): void
    {
        header('Content-Type: application/xrd+xml; charset=utf-8');
        $template = htmlspecialchars(AP_BASE_URL . '/.well-known/webfinger?resource={uri}', ENT_XML1 | ENT_QUOTES);
        echo '<?xml version="1.0" encoding="UTF-8"?>'
           . '<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">'
           . '<Link rel="lrdd" template="' . $template . '"/>'
           . '</XRD>';
        exit;
    }

    public function atprotoDid(array $p): void
    {
        if (!AP_ATPROTO_DID) { http_response_code(404); exit; }
        header('Content-Type: text/plain');
        echo AP_ATPROTO_DID;
    }

}
