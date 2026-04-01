<?php
declare(strict_types=1);

namespace App\Models;

class CryptoModel
{
    /** In-memory cache for public keys fetched during this request */
    private static array $keyCache = [];

    public static function generateKeyPair(): array
    {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($res, $priv);
        $pub = openssl_pkey_get_details($res)['key'];
        return [$priv, $pub];
    }

    /**
     * Sign an outgoing HTTP request.
     * Returns array of headers to add to the request.
     */
    public static function signRequest(
        string $method,
        string $url,
        string $privateKey,
        string $keyId,
        ?string $body = null
    ): array {
        $p    = parse_url($url);
        $host = $p['host'] ?? '';
        $path = ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        $date = gmdate('D, d M Y H:i:s \G\M\T');

        $signHeaders  = ['(request-target)', 'host', 'date'];
        $headerValues = [
            '(request-target)' => strtolower($method) . ' ' . $path,
            'host'             => $host,
            'date'             => $date,
        ];

        if ($body !== null) {
            $digest = 'SHA-256=' . base64_encode(hash('sha256', $body, true));
            $headerValues['digest']       = $digest;
            $headerValues['content-type'] = 'application/activity+json';
            $signHeaders[] = 'digest';
            $signHeaders[] = 'content-type';
        }

        $sigStr = implode("\n", array_map(
            fn($h) => "$h: " . $headerValues[$h],
            $signHeaders
        ));

        $key = openssl_pkey_get_private($privateKey);
        openssl_sign($sigStr, $sig, $key, OPENSSL_ALGO_SHA256);

        $sigHeader = sprintf(
            'keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"',
            $keyId,
            implode(' ', $signHeaders),
            base64_encode($sig)
        );

        $out = ['Host' => $host, 'Date' => $date, 'Signature' => $sigHeader];
        if ($body !== null) {
            $out['Digest']       = $headerValues['digest'];
            $out['Content-Type'] = 'application/activity+json';
        }
        return $out;
    }

    /**
     * Verify the HTTP Signature on an incoming request.
     * Returns true if valid, false otherwise.
     * On cache-miss failure, re-fetches the key once and retries (handles key rotation).
     */
    public static function verifyIncoming(array $headers, string $method, string $path, string $body = ''): bool
    {
        $sig = $headers['signature'] ?? '';
        if (!$sig) return false;

        if (!preg_match('/keyId="([^"]+)"/',    $sig, $km)) return false;
        if (!preg_match('/headers="([^"]+)"/',  $sig, $hm)) return false;
        if (!preg_match('/signature="([^"]+)"/', $sig, $sm)) return false;
        // Reject explicitly stated algorithms outside the accepted set.
        // hs2019 = "algorithm determined by key type" (IETF draft-cavage-http-signatures-12).
        // ed25519 = explicit EdDSA; accepted and handled in _verifySig().
        if (preg_match('/algorithm="([^"]+)"/', $sig, $am) &&
            !in_array(strtolower($am[1]), ['rsa-sha256', 'hs2019', 'ed25519'], true)) return false;

        $keyId   = $km[1];
        $hdrList = explode(' ', $hm[1]);
        $sigB64  = $sm[1];

        // hs2019 (IETF draft-cavage-http-signatures-12) supports (created) and (expires)
        // pseudo-headers whose values come from the Signature header parameters, not HTTP headers.
        $created = preg_match('/\bcreated=(\d+)\b/', $sig, $cm) ? $cm[1] : null;
        $expires = preg_match('/\bexpires=(\d+)\b/', $sig, $em) ? $em[1] : null;

        $parts = [];
        foreach ($hdrList as $h) {
            if ($h === '(request-target)') {
                $parts[] = "(request-target): " . strtolower($method) . ' ' . $path;
            } elseif ($h === '(created)' && $created !== null) {
                $parts[] = "(created): $created";
            } elseif ($h === '(expires)' && $expires !== null) {
                $parts[] = "(expires): $expires";
            } else {
                $parts[] = "$h: " . ($headers[$h] ?? '');
            }
        }
        $signingStr = implode("\n", $parts);

        // If the request carries a Digest header, verify it before checking the signature.
        // This protects the body integrity for signed inbox deliveries and matches Mastodon.
        $digestHeader = trim((string)($headers['digest'] ?? ''));
        if ($digestHeader !== '') {
            if (!preg_match('/^SHA-256=(.+)$/i', $digestHeader, $dm)) return false;
            $expectedDigest = base64_encode(hash('sha256', $body, true));
            if (!hash_equals($expectedDigest, trim($dm[1]))) return false;
        }

        // Reject requests with a stale Date header — allow ±12 hours (matches Mastodon).
        // 12 h accommodates delivery queues, retries, and clock skew across servers.
        $dateStr = $headers['date'] ?? '';
        if ($dateStr) {
            $ts = strtotime($dateStr);
            if ($ts === false || abs(time() - $ts) > 43200) return false;
        }

        $actorUrl = self::actorUrlFromKeyId($keyId);

        // First attempt with cached key (look up by specific keyId when available)
        $pub = self::fetchPublicKey($actorUrl, $keyId);
        if ($pub && self::_verifySig($signingStr, $sigB64, $pub)) return true;

        // If verification failed, the remote actor may have rotated their key.
        // Clear the cache and force a live re-fetch once, then retry.
        // IMPORTANT: do NOT delete the DB row before confirming the new key is fetchable —
        // if the fetch fails the actor would be permanently lost.
        $cacheKey = $keyId ?: $actorUrl;
        unset(self::$keyCache[$cacheKey]);
        $actor = RemoteActorModel::fetch($actorUrl, true); // force refresh
        if (!$actor) return false;
        $freshPem = self::extractKeyByIdFromRawJson($actor['raw_json'] ?? '', $keyId)
                 ?: ($actor['public_key'] ?? '');
        if (!$freshPem) return false;
        self::$keyCache[$cacheKey] = $freshPem;

        return self::_verifySig($signingStr, $sigB64, $freshPem);
    }

    /**
     * Verify a body-level Data Integrity proof (eddsa-jcs-2022).
     * Used as a fallback for servers that sign ActivityPub JSON bodies instead of
     * using HTTP Signatures on inbox deliveries.
     */
    public static function verifyObjectSignature(array $activity, string $actorId = ''): bool
    {
        $proof = $activity['proof'] ?? null;
        if (!is_array($proof)) return false;
        if (($proof['type'] ?? '') !== 'DataIntegrityProof') return false;
        if (($proof['cryptosuite'] ?? '') !== 'eddsa-jcs-2022') return false;
        if (($proof['proofPurpose'] ?? '') !== 'assertionMethod') return false;

        $verificationMethod = (string)($proof['verificationMethod'] ?? '');
        $proofValue         = (string)($proof['proofValue'] ?? '');
        if ($verificationMethod === '' || $proofValue === '') return false;

        $vmActor = self::actorUrlFromKeyId($verificationMethod);
        if ($actorId !== '') {
            $normActor = rtrim($actorId, '/');
            $normVm    = rtrim($vmActor, '/');
            if ($normActor !== $normVm) return false;
        }

        $created = (string)($proof['created'] ?? '');
        if ($created !== '') {
            $ts = strtotime($created);
            if ($ts === false || abs(time() - $ts) > 43200) return false;
        }

        $pub = self::fetchPublicKey($vmActor, $verificationMethod);
        if (!$pub) return false;

        $unsigned = $activity;
        unset($unsigned['proof']);
        $payload = self::jcsEncode($unsigned);
        if ($payload === null) return false;

        $sig = self::decodeMultibase($proofValue);
        if ($sig === '' || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) return false;

        $key = openssl_pkey_get_public($pub);
        if (!$key) return false;
        $details = openssl_pkey_get_details($key);
        if (($details['type'] ?? -1) !== 6) return false; // Ed25519

        $stripped = str_replace(["\n", "\r", "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"], '', $pub);
        $der = base64_decode(trim($stripped), true);
        if ($der === false || strlen($der) < 32) return false;
        return sodium_crypto_sign_verify_detached($sig, $payload, substr($der, -32));
    }

    private static function actorUrlFromKeyId(string $keyId): string
    {
        if (str_contains($keyId, '#')) {
            return preg_replace('/#.*$/', '', $keyId);
        }
        // GoToSocial-style path-based keyId (e.g. /main-key)
        if (preg_match('~^(https?://.+)/[a-z_-]+$~i', $keyId, $m)) {
            return $m[1];
        }
        return $keyId;
    }

    private static function _verifySig(string $signingStr, string $sigB64, string $pubPem): bool
    {
        $key = openssl_pkey_get_public($pubPem);
        if (!$key) return false;

        $details = openssl_pkey_get_details($key);
        // Ed25519 key type (EVP_PKEY_ED25519 = 6, PHP 8.1+ / OpenSSL 1.1.1+).
        // OPENSSL_KEYTYPE_ED25519 constant may not exist in all builds, so compare as int.
        if (($details['type'] ?? -1) === 6) {
            if (!function_exists('sodium_crypto_sign_verify_detached')) return false;
            // Extract raw 32-byte public key from Ed25519 SubjectPublicKeyInfo DER.
            // DER layout: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes key>
            $stripped = str_replace(["\n", "\r", "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"], '', $pubPem);
            $der = base64_decode(trim($stripped));
            if (strlen($der) < 32) return false;
            return sodium_crypto_sign_verify_detached(base64_decode($sigB64), $signingStr, substr($der, -32));
        }

        return openssl_verify($signingStr, base64_decode($sigB64), $key, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Fetch public key for a remote actor, using in-memory cache first.
     * When $keyId is given (e.g. "https://example.com/users/alice#main-key"),
     * searches the actor's raw_json for that specific key — handles multi-key actors.
     */
    public static function fetchPublicKey(string $actorUrl, string $keyId = ''): ?string
    {
        // 1. In-memory cache (keyed by keyId when available, else actorUrl)
        $cacheKey = $keyId ?: $actorUrl;
        if (isset(self::$keyCache[$cacheKey])) {
            return self::$keyCache[$cacheKey];
        }

        // 2. DB cache — also try the trailing-slash variant.
        // Some servers (Threads, etc.) have actor URLs with a trailing slash in the
        // keyId/activity but their actor document canonical id omits it (or vice-versa).
        $row = DB::one('SELECT public_key, raw_json FROM remote_actors WHERE id=?', [$actorUrl]);
        if (!$row) {
            $alt = str_ends_with($actorUrl, '/') ? rtrim($actorUrl, '/') : $actorUrl . '/';
            $row = DB::one('SELECT public_key, raw_json FROM remote_actors WHERE id=?', [$alt]);
        }
        if ($row) {
            $pem = self::extractKeyByIdFromRawJson($row['raw_json'] ?? '', $keyId)
                ?: ($row['public_key'] ?? '');
            if ($pem) {
                self::$keyCache[$cacheKey] = $pem;
                return $pem;
            }
        }

        // 3. Live fetch (actor not yet cached)
        $actor = RemoteActorModel::fetch($actorUrl);
        if ($actor) {
            $pem = self::extractKeyByIdFromRawJson($actor['raw_json'] ?? '', $keyId)
                ?: ($actor['public_key'] ?? '');
            if ($pem) {
                self::$keyCache[$cacheKey] = $pem;
                return $pem;
            }
        }

        return null;
    }

    /**
     * Extract a specific publicKeyPem from an actor's raw JSON by keyId.
     * Handles both single-key {"publicKey": {...}} and multi-key {"publicKey": [{...}, ...]}.
     * Falls back to the first key found when $keyId is empty or not matched.
     */
    private static function extractKeyByIdFromRawJson(string $rawJson, string $keyId): string
    {
        if (!$rawJson) return '';
        $d = json_decode($rawJson, true);
        if (!is_array($d)) return '';
        $candidates = [];
        foreach (['publicKey', 'assertionMethod'] as $field) {
            $value = $d[$field] ?? null;
            if (!is_array($value)) continue;
            if (isset($value['publicKeyPem']) || isset($value['publicKeyMultibase']) || isset($value['id'])) {
                $candidates[] = $value;
                continue;
            }
            foreach ($value as $item) {
                if (is_array($item)) $candidates[] = $item;
            }
        }

        $first = '';
        foreach ($candidates as $k) {
            $pem = '';
            if (is_string($k['publicKeyPem'] ?? null)) {
                $pem = (string)$k['publicKeyPem'];
            } elseif (is_string($k['publicKeyMultibase'] ?? null)) {
                $pem = self::multibaseToPem((string)$k['publicKeyMultibase']);
            }
            if ($pem === '') continue;
            if ($keyId && ($k['id'] ?? '') === $keyId) return $pem;
            if (!$first) $first = $pem;
        }
        return $keyId ? '' : $first;
    }

    private static function multibaseToPem(string $multibase): string
    {
        $decoded = self::decodeMultibase($multibase);
        if ($decoded === '' || substr($decoded, 0, 2) !== "\xed\x01") return '';
        $rawKey = substr($decoded, 2, 32);
        if (strlen($rawKey) !== 32) return '';
        $der = hex2bin('302a300506032b6570032100') . $rawKey;
        $b64 = chunk_split(base64_encode($der), 64, "\n");
        return "-----BEGIN PUBLIC KEY-----\n{$b64}-----END PUBLIC KEY-----\n";
    }

    private static function decodeMultibase(string $multibase): string
    {
        if (!str_starts_with($multibase, 'z')) return '';
        return self::base58Decode(substr($multibase, 1));
    }

    private static function base58Decode(string $input): string
    {
        if ($input === '') return '';
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $indexes  = array_flip(str_split($alphabet));
        $bytes    = [0];

        foreach (str_split($input) as $char) {
            if (!isset($indexes[$char])) return '';
            $carry = $indexes[$char];
            for ($i = count($bytes) - 1; $i >= 0; $i--) {
                $carry += $bytes[$i] * 58;
                $bytes[$i] = $carry & 0xff;
                $carry >>= 8;
            }
            while ($carry > 0) {
                array_unshift($bytes, $carry & 0xff);
                $carry >>= 8;
            }
        }

        $leadingZeros = 0;
        while ($leadingZeros < strlen($input) && $input[$leadingZeros] === '1') {
            $leadingZeros++;
        }

        return str_repeat("\x00", $leadingZeros) . pack('C*', ...$bytes);
    }

    private static function jcsEncode(mixed $value): ?string
    {
        if (is_null($value) || is_bool($value) || is_int($value)) {
            return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        if (is_float($value)) {
            if (!is_finite($value)) return null;
            return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
        }
        if (is_string($value)) {
            return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        if (is_array($value)) {
            if (array_is_list($value)) {
                $parts = [];
                foreach ($value as $item) {
                    $enc = self::jcsEncode($item);
                    if ($enc === null) return null;
                    $parts[] = $enc;
                }
                return '[' . implode(',', $parts) . ']';
            }

            $keys = array_keys($value);
            sort($keys, SORT_STRING);
            $parts = [];
            foreach ($keys as $key) {
                $encKey = json_encode((string)$key, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $encVal = self::jcsEncode($value[$key]);
                if ($encKey === false || $encVal === null) return null;
                $parts[] = $encKey . ':' . $encVal;
            }
            return '{' . implode(',', $parts) . '}';
        }
        return null;
    }
}
