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
    public static function verifyIncoming(array $headers, string $method, string $path, string $body = '', string $actorHint = ''): bool
    {
        return self::verifyIncomingDetailed($headers, $method, $path, $body, $actorHint)['ok'];
    }

    /**
     * Verify the HTTP Signature on an incoming request and return diagnostics.
     *
     * @return array{ok:bool,error:string,key_id:string,actor_url:string,algorithm:string,headers:string}
     */
    public static function verifyIncomingDetailed(array $headers, string $method, string $path, string $body = '', string $actorHint = ''): array
    {
        $sig = $headers['signature'] ?? '';
        if (!$sig) {
            return [
                'ok' => false,
                'error' => 'missing_signature_header',
                'key_id' => '',
                'actor_url' => '',
                'algorithm' => '',
                'headers' => '',
            ];
        }

        $signatureInput = trim((string)($headers['signature-input'] ?? ''));
        $modernSig = self::parseModernHttpSignature($headers, $method, $path, $body, $actorHint);
        if ($modernSig !== null) {
            return $modernSig;
        }

        $keyId = '';
        if (preg_match('/\bkeyid="([^"]+)"/i', $sig, $km)) {
            $keyId = $km[1];
        } elseif ($signatureInput !== '') {
            $parsedSigInput = self::parseLegacySignatureInput($signatureInput);
            if ($parsedSigInput !== null) {
                $keyId = $parsedSigInput['keyid'];
            }
        }

        if (!preg_match('/\bheaders="([^"]+)"/i', $sig, $hm)) {
            return [
                'ok' => false,
                'error' => 'signature_missing_headers_list',
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                'algorithm' => '',
                'headers' => '',
            ];
        }
        if (!preg_match('/\bsignature="([^"]+)"/i', $sig, $sm)) {
            return [
                'ok' => false,
                'error' => 'signature_missing_signature_value',
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                'algorithm' => '',
                'headers' => $hm[1],
            ];
        }
        // Reject explicitly stated algorithms outside the accepted set.
        // hs2019 = "algorithm determined by key type" (IETF draft-cavage-http-signatures-12).
        // ed25519 = explicit EdDSA; accepted and handled in _verifySig().
        // rsa-v1_5-sha256 is the modern HTTP Message Signatures identifier for
        // RSA PKCS#1 v1.5 with SHA-256, which matches our OpenSSL verification.
        $algorithm = preg_match('/\balgorithm="([^"]+)"/i', $sig, $am) ? strtolower($am[1]) : '';
        if ($algorithm !== '' && !in_array($algorithm, ['rsa-sha256', 'rsa-v1_5-sha256', 'hs2019', 'ed25519'], true)) {
            return [
                'ok' => false,
                'error' => 'unsupported_algorithm:' . $algorithm,
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }

        $hdrList = explode(' ', $hm[1]);
        $sigB64  = $sm[1];

        // hs2019 (IETF draft-cavage-http-signatures-12) supports (created) and (expires)
        // pseudo-headers whose values come from the Signature header parameters, not HTTP headers.
        $created = preg_match('/\bcreated=(\d+)\b/', $sig, $cm) ? $cm[1] : null;
        $expires = preg_match('/\bexpires=(\d+)\b/', $sig, $em) ? $em[1] : null;
        $timeError = self::validateSignatureTimeBounds($created, $expires);
        if ($timeError !== '') {
            return [
                'ok' => false,
                'error' => $timeError,
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }

        $parts = [];
        foreach ($hdrList as $h) {
            if ($h === '(request-target)') {
                $parts[] = "(request-target): " . strtolower($method) . ' ' . $path;
            } elseif ($h === '(created)' && $created !== null) {
                $parts[] = "(created): $created";
            } elseif ($h === '(expires)' && $expires !== null) {
                $parts[] = "(expires): $expires";
            } else {
                if (!array_key_exists($h, $headers)) {
                    return [
                        'ok' => false,
                        'error' => 'signed_header_missing:' . $h,
                        'key_id' => $keyId,
                        'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                        'algorithm' => $algorithm,
                        'headers' => $hm[1],
                    ];
                }
                $parts[] = "$h: " . $headers[$h];
            }
        }
        $signingStr = implode("\n", $parts);

        $digestError = self::verifyIncomingDigestHeaders($headers, $body);
        if ($digestError !== '') {
            return [
                'ok' => false,
                'error' => $digestError,
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }

        // Reject requests with a stale Date header — allow ±12 hours (matches Mastodon).
        // 12 h accommodates delivery queues, retries, and clock skew across servers.
        $dateStr = $headers['date'] ?? '';
        if ($dateStr) {
            $ts = strtotime($dateStr);
            if ($ts === false) {
                return [
                    'ok' => false,
                    'error' => 'date_header_invalid',
                    'key_id' => $keyId,
                    'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                    'algorithm' => $algorithm,
                    'headers' => $hm[1],
                ];
            }
            if (abs(time() - $ts) > 43200) {
                return [
                    'ok' => false,
                    'error' => 'date_header_stale',
                    'key_id' => $keyId,
                    'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                    'algorithm' => $algorithm,
                    'headers' => $hm[1],
                ];
            }
        }

        $actorUrl = $keyId !== '' ? self::actorUrlFromKeyId($keyId) : $actorHint;
        if ($actorUrl === '') {
            return [
                'ok' => false,
                'error' => 'signature_missing_keyid',
                'key_id' => '',
                'actor_url' => '',
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }

        // First attempt with cached key (look up by specific keyId when available).
        // Without keyId, only accept actors that expose a single unambiguous public key.
        $pub = $keyId !== ''
            ? self::fetchPublicKey($actorUrl, $keyId)
            : self::fetchSingleActorPublicKey($actorUrl);
        if (!$pub && $actorHint !== '' && rtrim($actorHint, '/') !== rtrim($actorUrl, '/')) {
            $pub = $keyId !== ''
                ? (self::fetchPublicKey($actorHint, $keyId) ?: self::fetchSingleActorPublicKey($actorHint))
                : self::fetchSingleActorPublicKey($actorHint);
        }
        if ($pub && self::_verifySig($signingStr, $sigB64, $pub)) {
            return [
                'ok' => true,
                'error' => '',
                'key_id' => $keyId,
                'actor_url' => $actorUrl,
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }

        // If verification failed, the remote actor may have rotated their key.
        // Clear the cache and force a live re-fetch once, then retry.
        // IMPORTANT: do NOT delete the DB row before confirming the new key is fetchable —
        // if the fetch fails the actor would be permanently lost.
        $cacheKey = $keyId ?: $actorUrl;
        unset(self::$keyCache[$cacheKey]);
        $actor = RemoteActorModel::fetch($actorUrl, true); // force refresh
        if (!$actor && $actorHint !== '' && rtrim($actorHint, '/') !== rtrim($actorUrl, '/')) {
            $actor = RemoteActorModel::fetch($actorHint, true);
            if ($actor) {
                $actorUrl = $actorHint;
            }
        }
        if (!$actor) {
            return [
                'ok' => false,
                'error' => $pub ? 'signature_mismatch_after_cached_key' : 'public_key_fetch_failed',
                'key_id' => $keyId,
                'actor_url' => $actorUrl,
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }
        $freshPem = $keyId !== ''
            ? self::extractKeyByIdFromRawJson($actor['raw_json'] ?? '', $keyId)
            : self::extractOnlyPublicKeyFromRawJson($actor['raw_json'] ?? '');
        if (!$freshPem) {
            return [
                'ok' => false,
                'error' => $keyId !== '' ? 'public_key_missing_for_keyid' : 'public_key_ambiguous_without_keyid',
                'key_id' => $keyId,
                'actor_url' => $actorUrl,
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }
        self::$keyCache[$cacheKey] = $freshPem;

        if (self::_verifySig($signingStr, $sigB64, $freshPem)) {
            return [
                'ok' => true,
                'error' => '',
                'key_id' => $keyId,
                'actor_url' => $actorUrl,
                'algorithm' => $algorithm,
                'headers' => $hm[1],
            ];
        }

        return [
            'ok' => false,
            'error' => $pub ? 'signature_mismatch_after_refresh' : 'signature_mismatch',
            'key_id' => $keyId,
            'actor_url' => $actorUrl,
            'algorithm' => $algorithm,
            'headers' => $hm[1],
        ];
    }

    /**
     * Minimal support for RFC 9421 HTTP Message Signatures.
     *
     * @return array{ok:bool,error:string,key_id:string,actor_url:string,algorithm:string,headers:string}|null
     */
    private static function parseModernHttpSignature(array $headers, string $method, string $path, string $body = '', string $actorHint = ''): ?array
    {
        $signatureInput = trim((string)($headers['signature-input'] ?? ''));
        $signature = trim((string)($headers['signature'] ?? ''));
        if ($signatureInput === '' || $signature === '') return null;

        if (!preg_match('/^\s*([A-Za-z][A-Za-z0-9_-]*)=\(([^)]*)\)(.*)$/', $signatureInput, $m)) {
            return null;
        }
        $label = $m[1];
        $componentsRaw = trim($m[2]);
        $paramsRaw = $m[3] ?? '';
        if (!preg_match('/(?:^|,)\s*' . preg_quote($label, '/') . '=:(.+?):\s*(?:,|$)/', $signature, $sm)) {
            return null;
        }

        $params = [];
        if (preg_match_all('/;([a-zA-Z0-9_-]+)=("(?:[^"\\\\]|\\\\.)*"|[0-9]+|[A-Za-z][A-Za-z0-9_:\-\/#.]*)/', $paramsRaw, $pm, PREG_SET_ORDER)) {
            foreach ($pm as $row) {
                $value = $row[2];
                if (strlen($value) >= 2 && $value[0] === '"' && substr($value, -1) === '"') {
                    $value = stripcslashes(substr($value, 1, -1));
                }
                $params[strtolower($row[1])] = $value;
            }
        }

        $keyId = trim((string)($params['keyid'] ?? ''));
        $alg = strtolower(trim((string)($params['alg'] ?? '')));
        if ($alg !== '' && !in_array($alg, ['rsa-sha256', 'rsa-v1_5-sha256', 'hs2019', 'ed25519'], true)) {
            return [
                'ok' => false,
                'error' => 'unsupported_algorithm:' . $alg,
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : '',
                'algorithm' => $alg,
                'headers' => $componentsRaw,
            ];
        }
        $timeError = self::validateSignatureTimeBounds(
            array_key_exists('created', $params) ? (string)$params['created'] : null,
            array_key_exists('expires', $params) ? (string)$params['expires'] : null
        );
        if ($timeError !== '') {
            return [
                'ok' => false,
                'error' => $timeError,
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : '',
                'algorithm' => $alg,
                'headers' => $componentsRaw,
            ];
        }

        $components = preg_split('/\s+/', $componentsRaw) ?: [];
        $parts = [];
        $covered = [];
        foreach ($components as $component) {
            $component = trim($component);
            if ($component === '') continue;
            if (strlen($component) >= 2 && $component[0] === '"' && substr($component, -1) === '"') {
                $component = substr($component, 1, -1);
            }
            $covered[] = $component;
            if ($component === '@method') {
                $parts[] = "\"@method\": " . strtoupper($method);
            } elseif ($component === '@target-uri') {
                $scheme = is_https_request() ? 'https' : 'http';
                $host = (string)($headers['host'] ?? AP_DOMAIN);
                $parts[] = "\"@target-uri\": " . $scheme . '://' . $host . $path;
            } elseif ($component === '@path') {
                $parts[] = "\"@path\": " . (string)(parse_url($path, PHP_URL_PATH) ?? '/');
            } elseif ($component === '@query') {
                $query = (string)(parse_url($path, PHP_URL_QUERY) ?? '');
                $parts[] = "\"@query\": ?" . $query;
            } elseif ($component === '@authority') {
                if (!array_key_exists('host', $headers)) {
                    return [
                        'ok' => false,
                        'error' => 'signed_header_missing:host',
                        'key_id' => $keyId,
                        'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : '',
                        'algorithm' => $alg,
                        'headers' => $componentsRaw,
                    ];
                }
                $parts[] = "\"@authority\": " . $headers['host'];
            } elseif (str_starts_with($component, '@')) {
                return null;
            } else {
                if (!array_key_exists($component, $headers)) {
                    return [
                        'ok' => false,
                        'error' => 'signed_header_missing:' . $component,
                        'key_id' => $keyId,
                        'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : '',
                        'algorithm' => $alg,
                        'headers' => $componentsRaw,
                    ];
                }
                $parts[] = '"' . $component . '": ' . $headers[$component];
            }
        }

        // RFC 9421 signs @signature-params exactly as serialized in
        // Signature-Input. Parameter order is significant; reordering
        // keyid/alg/created breaks signatures from implementations such as tags.pub.
        $parts[] = '"@signature-params": (' . $componentsRaw . ')' . $paramsRaw;
        $signingStr = implode("\n", $parts);

        $digestError = self::verifyIncomingDigestHeaders($headers, $body);
        if ($digestError !== '') {
            return [
                'ok' => false,
                'error' => $digestError,
                'key_id' => $keyId,
                'actor_url' => $keyId !== '' ? self::actorUrlFromKeyId($keyId) : ($actorHint !== '' ? $actorHint : ''),
                'algorithm' => $alg,
                'headers' => $componentsRaw,
            ];
        }

        $actorUrl = $keyId !== '' ? self::actorUrlFromKeyId($keyId) : $actorHint;
        if ($actorUrl === '') {
            return [
                'ok' => false,
                'error' => 'signature_missing_keyid',
                'key_id' => '',
                'actor_url' => '',
                'algorithm' => $alg,
                'headers' => $componentsRaw,
            ];
        }

        $pub = $keyId !== ''
            ? self::fetchPublicKey($actorUrl, $keyId)
            : self::fetchSingleActorPublicKey($actorUrl);
        if (!$pub) {
            return [
                'ok' => false,
                'error' => $keyId !== '' ? 'public_key_fetch_failed' : 'public_key_ambiguous_without_keyid',
                'key_id' => $keyId,
                'actor_url' => $actorUrl,
                'algorithm' => $alg,
                'headers' => $componentsRaw,
            ];
        }

        return self::_verifySig($signingStr, $sm[1], $pub)
            ? [
                'ok' => true,
                'error' => '',
                'key_id' => $keyId,
                'actor_url' => $actorUrl,
                'algorithm' => $alg,
                'headers' => $componentsRaw,
            ]
            : [
                'ok' => false,
                'error' => 'signature_mismatch',
                'key_id' => $keyId,
                'actor_url' => $actorUrl,
                'algorithm' => $alg,
                'headers' => $componentsRaw,
            ];
    }

    /**
     * Extract `keyid` from Signature-Input for legacy-style fallback logging/verification.
     *
     * @return array{keyid:string}|null
     */
    private static function parseLegacySignatureInput(string $signatureInput): ?array
    {
        if (!preg_match('/;keyid="([^"]+)"/i', $signatureInput, $m)) return null;
        return ['keyid' => $m[1]];
    }

    private static function verifyIncomingDigestHeaders(array $headers, string $body = ''): string
    {
        $digestHeader = trim((string)($headers['digest'] ?? ''));
        if ($digestHeader !== '') {
            if (!preg_match('/^SHA-256=(.+)$/i', $digestHeader, $dm)) {
                return 'digest_header_invalid';
            }
            $expectedDigest = base64_encode(hash('sha256', $body, true));
            if (!hash_equals($expectedDigest, trim($dm[1]))) {
                return 'digest_mismatch';
            }
        }

        $contentDigest = trim((string)($headers['content-digest'] ?? ''));
        if ($contentDigest !== '') {
            if (!preg_match('/sha-256=:(.+):/i', $contentDigest, $cm)) {
                return 'content_digest_header_invalid';
            }
            $expectedDigest = base64_encode(hash('sha256', $body, true));
            if (!hash_equals($expectedDigest, trim($cm[1]))) {
                return 'content_digest_mismatch';
            }
        }

        return '';
    }

    private static function validateSignatureTimeBounds(?string $created, ?string $expires): string
    {
        $now = time();
        $createdTs = null;
        $expiresTs = null;

        if ($created !== null) {
            if (!preg_match('/^\d+$/', $created)) return 'signature_created_invalid';
            $createdTs = (int)$created;
            if (abs($now - $createdTs) > 43200) return 'signature_created_stale';
        }

        if ($expires !== null) {
            if (!preg_match('/^\d+$/', $expires)) return 'signature_expires_invalid';
            $expiresTs = (int)$expires;
            if ($expiresTs < $now) return 'signature_expired';
        }

        if ($createdTs !== null && $expiresTs !== null && $expiresTs < $createdTs) {
            return 'signature_expires_before_created';
        }

        return '';
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

        if (!defined('SODIUM_CRYPTO_SIGN_BYTES') || !function_exists('sodium_crypto_sign_verify_detached')) {
            return false;
        }

        $sig = self::decodeMultibase($proofValue);
        if ($sig === '' || strlen($sig) !== \SODIUM_CRYPTO_SIGN_BYTES) return false;

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
            $der = base64_decode(trim($stripped), true);
            $sigRaw = base64_decode($sigB64, true);
            if ($der === false || $sigRaw === false || strlen($der) < 32) return false;
            return sodium_crypto_sign_verify_detached($sigRaw, $signingStr, substr($der, -32));
        }

        $sigRaw = base64_decode($sigB64, true);
        if ($sigRaw === false) return false;
        return openssl_verify($signingStr, $sigRaw, $key, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Fetch public key for a remote actor, using in-memory cache first.
     * When $keyId is given (e.g. "https://example.com/users/alice#main-key"),
     * searches the actor's raw_json for that specific key — handles multi-key actors.
     */
    public static function fetchPublicKey(string $actorUrl, string $keyId = ''): ?string
    {
        return self::fetchPublicKeyDetailed($actorUrl, $keyId)['pem'] ?: null;
    }

    /**
     * Fetch public key for a remote actor with diagnostics.
     *
     * @return array{pem:string,error:string}
     */
    private static function fetchPublicKeyDetailed(string $actorUrl, string $keyId = ''): array
    {
        // 1. In-memory cache (keyed by keyId when available, else actorUrl)
        $cacheKey = $keyId ?: $actorUrl;
        if (isset(self::$keyCache[$cacheKey])) {
            return ['pem' => self::$keyCache[$cacheKey], 'error' => ''];
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
                return ['pem' => $pem, 'error' => ''];
            }
        }

        // 3. Live fetch (actor not yet cached)
        $actorResult = RemoteActorModel::fetchDetailed($actorUrl);
        $actor = $actorResult['actor'];
        if ($actor) {
            $pem = self::extractKeyByIdFromRawJson($actor['raw_json'] ?? '', $keyId)
                ?: ($actor['public_key'] ?? '');
            if ($pem) {
                self::$keyCache[$cacheKey] = $pem;
                return ['pem' => $pem, 'error' => ''];
            }
        }

        return [
            'pem' => '',
            'error' => $actorResult['ok']
                ? ($keyId !== '' ? 'public_key_missing_for_keyid' : 'public_key_missing')
                : ('actor_fetch_failed:' . $actorResult['error']),
        ];
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
        $candidates = self::extractKeyCandidates($d);

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

    private static function extractOnlyPublicKeyFromRawJson(string $rawJson): string
    {
        if (!$rawJson) return '';
        $d = json_decode($rawJson, true);
        if (!is_array($d)) return '';
        $candidates = self::extractKeyCandidates($d);
        $unique = [];
        foreach ($candidates as $k) {
            $pem = '';
            if (is_string($k['publicKeyPem'] ?? null)) {
                $pem = (string)$k['publicKeyPem'];
            } elseif (is_string($k['publicKeyMultibase'] ?? null)) {
                $pem = self::multibaseToPem((string)$k['publicKeyMultibase']);
            }
            if ($pem === '') continue;
            $unique[sha1($pem)] = $pem;
        }
        return count($unique) === 1 ? (string)reset($unique) : '';
    }

    private static function extractKeyCandidates(array $d): array
    {
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
        return $candidates;
    }

    private static function fetchSingleActorPublicKey(string $actorUrl): ?string
    {
        if ($actorUrl === '') return null;
        $row = DB::one('SELECT raw_json, public_key FROM remote_actors WHERE id=?', [$actorUrl]);
        if ($row) {
            $pem = self::extractOnlyPublicKeyFromRawJson((string)($row['raw_json'] ?? ''));
            if ($pem !== '') return $pem;
            if (trim((string)($row['public_key'] ?? '')) !== '' && trim((string)($row['raw_json'] ?? '')) === '') {
                return trim((string)$row['public_key']);
            }
        }
        $actor = RemoteActorModel::fetch($actorUrl, true);
        if (!$actor) return null;
        $pem = self::extractOnlyPublicKeyFromRawJson((string)($actor['raw_json'] ?? ''));
        return $pem !== '' ? $pem : null;
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

    // ══════════════════════════════════════════════════════════
    // RsaSignature2017 (Linked Data Signature) verification
    // ══════════════════════════════════════════════════════════

    /**
     * Verify an RsaSignature2017 body signature.
     * Implements JSON-LD URDNA2015 canonicalization for ActivityPub documents.
     */
    public static function verifyRsaSignature2017(array $activity, string $actorId = ''): bool
    {
        return self::verifyRsaSignature2017Detailed($activity, $actorId)['ok'];
    }

    /**
     * Verify an RsaSignature2017 body signature with diagnostics.
     *
     * @return array{ok:bool,error:string,key_id:string,actor_url:string}
     */
    public static function verifyRsaSignature2017Detailed(array $activity, string $actorId = ''): array
    {
        $sig = $activity['signature'] ?? null;
        if (!is_array($sig) || ($sig['type'] ?? '') !== 'RsaSignature2017') {
            return ['ok' => false, 'error' => 'missing_rsa_signature_2017', 'key_id' => '', 'actor_url' => ''];
        }

        $sigValue = (string)($sig['signatureValue'] ?? '');
        $creator  = (string)($sig['creator'] ?? '');
        if ($sigValue === '' || $creator === '') {
            return ['ok' => false, 'error' => 'signature_fields_missing', 'key_id' => $creator, 'actor_url' => ''];
        }

        // Options use the legacy identity context, matching Mastodon's
        // LinkedDataSignature implementation for RsaSignature2017.
        $options = $sig;
        unset($options['type'], $options['id'], $options['signatureValue']);
        $options['@context'] = 'https://w3id.org/identity/v1';

        // Document: activity minus signature
        $document = $activity;
        unset($document['signature']);

        $optCanon = self::ldNormalize($options);
        $docCanon = self::ldNormalize($document);
        if ($optCanon === null || $docCanon === null) {
            return ['ok' => false, 'error' => 'jsonld_normalization_failed', 'key_id' => $creator, 'actor_url' => self::actorUrlFromKeyId($creator)];
        }

        // Mastodon-compatible LD signatures concatenate lowercase SHA-256 hex digests,
        // not raw binary hashes, before RSA verification.
        $toVerify = hash('sha256', $optCanon) . hash('sha256', $docCanon);

        $keyActor = self::actorUrlFromKeyId($creator);
        if ($actorId !== '' && rtrim($keyActor, '/') !== rtrim($actorId, '/')) {
            return ['ok' => false, 'error' => 'creator_actor_mismatch', 'key_id' => $creator, 'actor_url' => $keyActor];
        }

        $pub = self::fetchPublicKeyDetailed($keyActor, $creator);
        if ($pub['pem'] === '') {
            return ['ok' => false, 'error' => $pub['error'], 'key_id' => $creator, 'actor_url' => $keyActor];
        }

        $key = openssl_pkey_get_public($pub['pem']);
        if (!$key) {
            return ['ok' => false, 'error' => 'public_key_invalid_pem', 'key_id' => $creator, 'actor_url' => $keyActor];
        }

        $sigRaw = base64_decode($sigValue, true);
        if ($sigRaw === false) {
            return ['ok' => false, 'error' => 'signature_base64_invalid', 'key_id' => $creator, 'actor_url' => $keyActor];
        }

        return openssl_verify($toVerify, $sigRaw, $key, OPENSSL_ALGO_SHA256) === 1
            ? ['ok' => true, 'error' => '', 'key_id' => $creator, 'actor_url' => $keyActor]
            : ['ok' => false, 'error' => 'rsa_signature_mismatch', 'key_id' => $creator, 'actor_url' => $keyActor];
    }

    /**
     * Normalize a JSON-LD document using URDNA2015.
     * Returns canonical N-Quads string, or null on failure.
     */
    private static function ldNormalize(array $doc): ?string
    {
        $ctx = self::ldResolveContext($doc['@context'] ?? []);
        $expanded = self::ldExpandNode($doc, $ctx);
        if ($expanded === null) return null;

        $quads = [];
        $bn = 0;
        self::ldToQuads($expanded, $quads, $bn);

        return self::urdna2015($quads);
    }

    // ── Context resolution ───────────────────────────────────

    /** Hardcoded JSON-LD context definitions (raw, with prefixes unexpanded). */
    private static function ldKnownContextDefs(): array
    {
        static $c = null;
        if ($c !== null) return $c;

        $sec = [
            'id' => '@id', 'type' => '@type',
            'dc' => 'http://purl.org/dc/terms/',
            'sec' => 'https://w3id.org/security#',
            'xsd' => 'http://www.w3.org/2001/XMLSchema#',
            'CryptographicKey' => 'sec:Key',
            'EcdsaKoblitzSignature2016' => 'sec:EcdsaKoblitzSignature2016',
            'Ed25519Signature2018' => 'sec:Ed25519Signature2018',
            'EncryptedMessage' => 'sec:EncryptedMessage',
            'GraphSignature2012' => 'sec:GraphSignature2012',
            'LinkedDataSignature2015' => 'sec:LinkedDataSignature2015',
            'LinkedDataSignature2016' => 'sec:LinkedDataSignature2016',
            'authenticationTag' => 'sec:authenticationTag',
            'canonicalizationAlgorithm' => 'sec:canonicalizationAlgorithm',
            'cipherAlgorithm' => 'sec:cipherAlgorithm',
            'cipherData' => 'sec:cipherData',
            'cipherKey' => 'sec:cipherKey',
            'created' => ['@id' => 'dc:created', '@type' => 'xsd:dateTime'],
            'creator' => ['@id' => 'dc:creator', '@type' => '@id'],
            'digestAlgorithm' => 'sec:digestAlgorithm',
            'digestValue' => 'sec:digestValue',
            'domain' => 'sec:domain',
            'encryptionKey' => 'sec:encryptionKey',
            'expiration' => ['@id' => 'sec:expiration', '@type' => 'xsd:dateTime'],
            'expires' => ['@id' => 'sec:expiration', '@type' => 'xsd:dateTime'],
            'initializationVector' => 'sec:initializationVector',
            'iterationCount' => 'sec:iterationCount',
            'nonce' => 'sec:nonce',
            'normalizationAlgorithm' => 'sec:normalizationAlgorithm',
            'owner' => ['@id' => 'sec:owner', '@type' => '@id'],
            'password' => 'sec:password',
            'privateKey' => ['@id' => 'sec:privateKey', '@type' => '@id'],
            'privateKeyPem' => 'sec:privateKeyPem',
            'publicKey' => ['@id' => 'sec:publicKey', '@type' => '@id'],
            'publicKeyBase58' => 'sec:publicKeyBase58',
            'publicKeyPem' => 'sec:publicKeyPem',
            'publicKeyWif' => 'sec:publicKeyWif',
            'publicKeyService' => ['@id' => 'sec:publicKeyService', '@type' => '@id'],
            'revoked' => ['@id' => 'sec:revoked', '@type' => 'xsd:dateTime'],
            'salt' => 'sec:salt',
            'signature' => 'sec:signature',
            'signatureAlgorithm' => 'sec:signingAlgorithm',
            'signatureValue' => 'sec:signatureValue',
        ];

        $as = [
            '@vocab' => '_:',
            'xsd' => 'http://www.w3.org/2001/XMLSchema#',
            'as' => 'https://www.w3.org/ns/activitystreams#',
            'ldp' => 'http://www.w3.org/ns/ldp#',
            'vcard' => 'http://www.w3.org/2006/vcard/ns#',
            'id' => '@id', 'type' => '@type',
            'Accept' => 'as:Accept', 'Activity' => 'as:Activity',
            'IntransitiveActivity' => 'as:IntransitiveActivity',
            'Add' => 'as:Add', 'Announce' => 'as:Announce',
            'Application' => 'as:Application', 'Arrive' => 'as:Arrive',
            'Article' => 'as:Article', 'Audio' => 'as:Audio',
            'Block' => 'as:Block', 'Collection' => 'as:Collection',
            'CollectionPage' => 'as:CollectionPage',
            'Relationship' => 'as:Relationship',
            'Create' => 'as:Create', 'Delete' => 'as:Delete',
            'Dislike' => 'as:Dislike', 'Document' => 'as:Document',
            'Event' => 'as:Event', 'Follow' => 'as:Follow',
            'Flag' => 'as:Flag', 'Group' => 'as:Group',
            'Ignore' => 'as:Ignore', 'Image' => 'as:Image',
            'Invite' => 'as:Invite', 'Join' => 'as:Join',
            'Leave' => 'as:Leave', 'Like' => 'as:Like',
            'Link' => 'as:Link', 'Mention' => 'as:Mention',
            'Note' => 'as:Note', 'Object' => 'as:Object',
            'Offer' => 'as:Offer',
            'OrderedCollection' => 'as:OrderedCollection',
            'OrderedCollectionPage' => 'as:OrderedCollectionPage',
            'Organization' => 'as:Organization', 'Page' => 'as:Page',
            'Person' => 'as:Person', 'Place' => 'as:Place',
            'Profile' => 'as:Profile', 'Question' => 'as:Question',
            'Reject' => 'as:Reject', 'Remove' => 'as:Remove',
            'Service' => 'as:Service',
            'TentativeAccept' => 'as:TentativeAccept',
            'TentativeReject' => 'as:TentativeReject',
            'Tombstone' => 'as:Tombstone', 'Undo' => 'as:Undo',
            'Update' => 'as:Update', 'Video' => 'as:Video',
            'View' => 'as:View', 'Listen' => 'as:Listen',
            'Read' => 'as:Read', 'Move' => 'as:Move',
            'Travel' => 'as:Travel',
            'IsFollowing' => 'as:IsFollowing',
            'IsFollowedBy' => 'as:IsFollowedBy',
            'IsContact' => 'as:IsContact', 'IsMember' => 'as:IsMember',
            'subject' => ['@id' => 'as:subject', '@type' => '@id'],
            'relationship' => ['@id' => 'as:relationship', '@type' => '@id'],
            'actor' => ['@id' => 'as:actor', '@type' => '@id'],
            'attributedTo' => ['@id' => 'as:attributedTo', '@type' => '@id'],
            'attachment' => ['@id' => 'as:attachment', '@type' => '@id'],
            'bcc' => ['@id' => 'as:bcc', '@type' => '@id'],
            'bto' => ['@id' => 'as:bto', '@type' => '@id'],
            'cc' => ['@id' => 'as:cc', '@type' => '@id'],
            'context' => ['@id' => 'as:context', '@type' => '@id'],
            'current' => ['@id' => 'as:current', '@type' => '@id'],
            'first' => ['@id' => 'as:first', '@type' => '@id'],
            'generator' => ['@id' => 'as:generator', '@type' => '@id'],
            'icon' => ['@id' => 'as:icon', '@type' => '@id'],
            'image' => ['@id' => 'as:image', '@type' => '@id'],
            'inReplyTo' => ['@id' => 'as:inReplyTo', '@type' => '@id'],
            'items' => ['@id' => 'as:items', '@type' => '@id'],
            'instrument' => ['@id' => 'as:instrument', '@type' => '@id'],
            'last' => ['@id' => 'as:last', '@type' => '@id'],
            'location' => ['@id' => 'as:location', '@type' => '@id'],
            'next' => ['@id' => 'as:next', '@type' => '@id'],
            'object' => ['@id' => 'as:object', '@type' => '@id'],
            'oneOf' => ['@id' => 'as:oneOf', '@type' => '@id'],
            'anyOf' => ['@id' => 'as:anyOf', '@type' => '@id'],
            'closed' => ['@id' => 'as:closed', '@type' => 'xsd:dateTime'],
            'origin' => ['@id' => 'as:origin', '@type' => '@id'],
            'accuracy' => ['@id' => 'as:accuracy', '@type' => 'xsd:float'],
            'prev' => ['@id' => 'as:prev', '@type' => '@id'],
            'preview' => ['@id' => 'as:preview', '@type' => '@id'],
            'replies' => ['@id' => 'as:replies', '@type' => '@id'],
            'result' => ['@id' => 'as:result', '@type' => '@id'],
            'audience' => ['@id' => 'as:audience', '@type' => '@id'],
            'partOf' => ['@id' => 'as:partOf', '@type' => '@id'],
            'tag' => ['@id' => 'as:tag', '@type' => '@id'],
            'target' => ['@id' => 'as:target', '@type' => '@id'],
            'to' => ['@id' => 'as:to', '@type' => '@id'],
            'url' => ['@id' => 'as:url', '@type' => '@id'],
            'altitude' => ['@id' => 'as:altitude', '@type' => 'xsd:float'],
            'content' => 'as:content',
            'name' => 'as:name',
            'duration' => ['@id' => 'as:duration', '@type' => 'xsd:duration'],
            'endTime' => ['@id' => 'as:endTime', '@type' => 'xsd:dateTime'],
            'height' => ['@id' => 'as:height', '@type' => 'xsd:nonNegativeInteger'],
            'href' => ['@id' => 'as:href', '@type' => '@id'],
            'hreflang' => 'as:hreflang',
            'latitude' => ['@id' => 'as:latitude', '@type' => 'xsd:float'],
            'longitude' => ['@id' => 'as:longitude', '@type' => 'xsd:float'],
            'mediaType' => 'as:mediaType',
            'published' => ['@id' => 'as:published', '@type' => 'xsd:dateTime'],
            'radius' => ['@id' => 'as:radius', '@type' => 'xsd:float'],
            'rel' => 'as:rel',
            'startIndex' => ['@id' => 'as:startIndex', '@type' => 'xsd:nonNegativeInteger'],
            'startTime' => ['@id' => 'as:startTime', '@type' => 'xsd:dateTime'],
            'summary' => 'as:summary',
            'totalItems' => ['@id' => 'as:totalItems', '@type' => 'xsd:nonNegativeInteger'],
            'units' => 'as:units',
            'updated' => ['@id' => 'as:updated', '@type' => 'xsd:dateTime'],
            'width' => ['@id' => 'as:width', '@type' => 'xsd:nonNegativeInteger'],
            'describes' => ['@id' => 'as:describes', '@type' => '@id'],
            'formerType' => ['@id' => 'as:formerType', '@type' => '@id'],
            'deleted' => ['@id' => 'as:deleted', '@type' => 'xsd:dateTime'],
            'inbox' => ['@id' => 'ldp:inbox', '@type' => '@id'],
            'outbox' => ['@id' => 'as:outbox', '@type' => '@id'],
            'following' => ['@id' => 'as:following', '@type' => '@id'],
            'followers' => ['@id' => 'as:followers', '@type' => '@id'],
            'streams' => ['@id' => 'as:streams', '@type' => '@id'],
            'preferredUsername' => 'as:preferredUsername',
            'endpoints' => ['@id' => 'as:endpoints', '@type' => '@id'],
            'uploadMedia' => ['@id' => 'as:uploadMedia', '@type' => '@id'],
            'proxyUrl' => ['@id' => 'as:proxyUrl', '@type' => '@id'],
            'liked' => ['@id' => 'as:liked', '@type' => '@id'],
            'oauthAuthorizationEndpoint' => ['@id' => 'as:oauthAuthorizationEndpoint', '@type' => '@id'],
            'oauthTokenEndpoint' => ['@id' => 'as:oauthTokenEndpoint', '@type' => '@id'],
            'provideClientKey' => ['@id' => 'as:provideClientKey', '@type' => '@id'],
            'signClientKey' => ['@id' => 'as:signClientKey', '@type' => '@id'],
            'sharedInbox' => ['@id' => 'as:sharedInbox', '@type' => '@id'],
            'Public' => ['@id' => 'as:Public', '@type' => '@id'],
            'source' => 'as:source',
            'likes' => ['@id' => 'as:likes', '@type' => '@id'],
            'shares' => ['@id' => 'as:shares', '@type' => '@id'],
            'alsoKnownAs' => ['@id' => 'as:alsoKnownAs', '@type' => '@id'],
        ];

        $c = [
            'https://w3id.org/security/v1' => $sec,
            'https://w3id.org/identity/v1' => $sec, // superset; security terms are identical
            'https://www.w3.org/ns/activitystreams' => $as,
        ];
        return $c;
    }

    /**
     * Resolve a @context value into a flat map of term → definition.
     * Definitions are: '@id'/'@type' for keywords, string IRI for aliases,
     * or array ['@id'=>IRI, '@type'=>IRI] for typed terms.
     * Prefixes are stored as 'prefix' => 'http://...#' or 'http://.../' entries.
     */
    private static function ldResolveContext(mixed $ctxVal): array
    {
        if (is_string($ctxVal)) {
            $known = self::ldKnownContextDefs();
            return self::ldCompileCtx($known[$ctxVal] ?? []);
        }
        if (!is_array($ctxVal)) return [];

        if (array_is_list($ctxVal)) {
            $merged = [];
            foreach ($ctxVal as $item) {
                $resolved = self::ldResolveContext($item);
                $merged = array_merge($merged, $resolved);
            }
            return $merged;
        }

        // Inline context object
        return self::ldCompileCtx($ctxVal);
    }

    /**
     * Compile a raw context definition into a resolved map with fully expanded IRIs.
     */
    private static function ldCompileCtx(array $raw): array
    {
        $prefixes = [];
        $terms = [];

        // First pass: extract prefixes (string values ending in # or /)
        foreach ($raw as $k => $v) {
            if (str_starts_with($k, '@')) {
                $terms[$k] = $v;
                continue;
            }
            if (is_string($v) && ($v === '@id' || $v === '@type')) {
                $terms[$k] = $v;
                continue;
            }
            if (is_string($v) && (str_ends_with($v, '#') || str_ends_with($v, '/'))) {
                // Could be a prefix OR a term that expands to a namespace
                // Check if it looks like a prefix (short name, value is a namespace URI)
                if (!str_contains($v, ':') || str_starts_with($v, 'http://') || str_starts_with($v, 'https://')) {
                    $prefixes[$k] = $v;
                }
            }
        }

        // Second pass: expand all terms using prefixes
        foreach ($raw as $k => $v) {
            if (str_starts_with($k, '@')) continue;
            if (isset($prefixes[$k])) {
                $terms[$k] = $prefixes[$k]; // prefix definition
                continue;
            }

            if (is_string($v)) {
                $expanded = self::ldExpandIri($v, $prefixes);
                $terms[$k] = $expanded;
            } elseif (is_array($v)) {
                $def = [];
                if (isset($v['@id'])) {
                    $def['@id'] = self::ldExpandIri((string)$v['@id'], $prefixes);
                }
                if (isset($v['@type'])) {
                    $t = (string)$v['@type'];
                    $def['@type'] = ($t === '@id') ? '@id' : self::ldExpandIri($t, $prefixes);
                }
                if (isset($v['@container'])) {
                    $def['@container'] = $v['@container'];
                }
                $terms[$k] = $def;
            }
        }

        return $terms;
    }

    /** Expand a compact IRI (e.g. "as:Follow") using prefix map. */
    private static function ldExpandIri(string $val, array $prefixes): string
    {
        if ($val === '@id' || $val === '@type') return $val;
        if (str_starts_with($val, 'http://') || str_starts_with($val, 'https://')) return $val;
        if (str_contains($val, ':')) {
            $parts = explode(':', $val, 2);
            if (isset($prefixes[$parts[0]])) {
                return $prefixes[$parts[0]] . $parts[1];
            }
        }
        return $val;
    }

    // ── JSON-LD expansion ────────────────────────────────────

    /**
     * Expand a JSON-LD node into its expanded form.
     * Returns ['@id'=>..., '@type'=>[...], 'iri'=>[values...], ...] or null.
     */
    private static function ldExpandNode(array $node, array $ctx): ?array
    {
        // Merge local @context if present
        if (isset($node['@context'])) {
            $localCtx = self::ldResolveContext($node['@context']);
            $ctx = array_merge($ctx, $localCtx);
        }

        $result = [];
        $vocab = $ctx['@vocab'] ?? '';

        foreach ($node as $key => $value) {
            if ($key === '@context') continue;

            // Resolve key to IRI
            $iri = self::ldTermToIri($key, $ctx, $vocab);
            if ($iri === null) continue; // unmappable term

            if ($iri === '@id') {
                $result['@id'] = self::ldExpandValueIri((string)$value, $ctx);
                continue;
            }
            if ($iri === '@type') {
                $types = is_array($value) ? $value : [$value];
                $result['@type'] = array_map(fn($t) => self::ldExpandTypeIri((string)$t, $ctx, $vocab), $types);
                continue;
            }

            // Skip blank-node predicates (_:xxx) — they're not valid RDF
            if (str_starts_with($iri, '_:')) continue;

            // Determine term type coercion
            $termDef = $ctx[$key] ?? null;
            $typeCoerce = null;
            if (is_array($termDef) && isset($termDef['@type'])) {
                $typeCoerce = $termDef['@type'];
            }

            // Expand value(s)
            $values = is_array($value) && array_is_list($value) ? $value : [$value];
            $expanded = [];
            foreach ($values as $v) {
                $ev = self::ldExpandValue($v, $ctx, $typeCoerce, $vocab);
                if ($ev !== null) $expanded[] = $ev;
            }
            if ($expanded !== []) {
                $result[$iri] = $expanded;
            }
        }

        return $result ?: null;
    }

    /** Resolve a term name to its predicate IRI using context. */
    private static function ldTermToIri(string $term, array $ctx, string $vocab): ?string
    {
        // Already a full IRI
        if (str_starts_with($term, 'http://') || str_starts_with($term, 'https://')) return $term;

        // Defined in context
        if (isset($ctx[$term])) {
            $def = $ctx[$term];
            if (is_string($def)) return ($def === '@id' || $def === '@type') ? $def : $def;
            if (is_array($def) && isset($def['@id'])) return $def['@id'];
        }

        // Compact IRI (prefix:suffix)
        if (str_contains($term, ':')) {
            [$prefix, $suffix] = explode(':', $term, 2);
            if (isset($ctx[$prefix]) && is_string($ctx[$prefix])) {
                return $ctx[$prefix] . $suffix;
            }
        }

        // @vocab fallback
        if ($vocab !== '') return $vocab . $term;

        return null;
    }

    /** Expand a value IRI (used for @id values). */
    private static function ldExpandValueIri(string $val, array $ctx): string
    {
        if (str_starts_with($val, 'http://') || str_starts_with($val, 'https://')) return $val;
        if (str_contains($val, ':')) {
            [$prefix, $suffix] = explode(':', $val, 2);
            if (isset($ctx[$prefix]) && is_string($ctx[$prefix])) {
                return $ctx[$prefix] . $suffix;
            }
        }
        return $val;
    }

    /** Expand a @type value to its full IRI. */
    private static function ldExpandTypeIri(string $val, array $ctx, string $vocab): string
    {
        if (str_starts_with($val, 'http://') || str_starts_with($val, 'https://')) return $val;
        // Check if it's a defined type alias
        if (isset($ctx[$val])) {
            $def = $ctx[$val];
            if (is_string($def) && $def !== '@id' && $def !== '@type') return $def;
            if (is_array($def) && isset($def['@id'])) return $def['@id'];
        }
        // Compact IRI
        if (str_contains($val, ':')) {
            [$prefix, $suffix] = explode(':', $val, 2);
            if (isset($ctx[$prefix]) && is_string($ctx[$prefix])) {
                return $ctx[$prefix] . $suffix;
            }
        }
        if ($vocab !== '' && !str_starts_with($vocab, '_:')) return $vocab . $val;
        return $val;
    }

    /** Expand a single property value. Returns expanded value representation. */
    private static function ldExpandValue(mixed $val, array $ctx, ?string $typeCoerce, string $vocab): ?array
    {
        if ($val === null) return null;

        // Nested object
        if (is_array($val) && !array_is_list($val)) {
            $expanded = self::ldExpandNode($val, $ctx);
            return $expanded;
        }

        // IRI coercion
        if ($typeCoerce === '@id') {
            if (is_string($val)) {
                return ['@id' => self::ldExpandValueIri($val, $ctx)];
            }
            return null;
        }

        // Typed literal
        if (is_string($val)) {
            if ($typeCoerce !== null) {
                return ['@value' => $val, '@type' => $typeCoerce];
            }
            return ['@value' => $val];
        }

        // Boolean/numeric
        if (is_bool($val)) {
            return ['@value' => $val ? 'true' : 'false', '@type' => 'http://www.w3.org/2001/XMLSchema#boolean'];
        }
        if (is_int($val)) {
            return ['@value' => (string)$val, '@type' => 'http://www.w3.org/2001/XMLSchema#integer'];
        }
        if (is_float($val)) {
            $s = sprintf('%E', $val);
            // Normalize: 1.000000E+0 → 1.0E0, match xsd:double canonical form
            $s = preg_replace('/(\.\d*?)0+(E[+-]?)0*(\d+)/', '$1$2$3', $s);
            if (!str_contains($s, '.')) $s = str_replace('E', '.0E', $s);
            return ['@value' => $s, '@type' => 'http://www.w3.org/2001/XMLSchema#double'];
        }

        return null;
    }

    // ── N-Quads generation ───────────────────────────────────

    /**
     * Convert an expanded JSON-LD node into N-Quads triples.
     * Each quad: ['s'=>subject, 'p'=>predicate, 'o'=>objectMap]
     * where objectMap has @id (IRI/bnode) or @value+optional @type/@language.
     */
    private static function ldToQuads(array $node, array &$quads, int &$bn, string $parentSubject = ''): string
    {
        $subject = $node['@id'] ?? ('_:b' . ($bn++));

        // @type triples
        foreach ($node['@type'] ?? [] as $typeIri) {
            if (str_starts_with($typeIri, '_:')) continue; // skip blank-node types
            $quads[] = ['s' => $subject, 'p' => 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', 'o' => ['@id' => $typeIri]];
        }

        // Property triples
        foreach ($node as $pred => $values) {
            if (str_starts_with($pred, '@')) continue; // skip keywords
            if (!is_array($values)) continue;

            foreach ($values as $val) {
                if (!is_array($val)) continue;

                if (isset($val['@id'])) {
                    // IRI or nested node
                    if (count($val) === 1) {
                        // Simple IRI reference
                        $quads[] = ['s' => $subject, 'p' => $pred, 'o' => ['@id' => $val['@id']]];
                    } else {
                        // Nested node — recurse
                        $nestedSubject = self::ldToQuads($val, $quads, $bn, $subject);
                        $quads[] = ['s' => $subject, 'p' => $pred, 'o' => ['@id' => $nestedSubject]];
                    }
                } elseif (array_key_exists('@value', $val)) {
                    $quads[] = ['s' => $subject, 'p' => $pred, 'o' => $val];
                } elseif (isset($val['@type']) || isset($val['http://www.w3.org/1999/02/22-rdf-syntax-ns#type'])) {
                    // Nested blank node (has @type but no @id)
                    $nestedSubject = self::ldToQuads($val, $quads, $bn, $subject);
                    $quads[] = ['s' => $subject, 'p' => $pred, 'o' => ['@id' => $nestedSubject]];
                } else {
                    // Other nested object without @id
                    $hasProps = false;
                    foreach ($val as $k => $v) {
                        if (!str_starts_with($k, '@')) { $hasProps = true; break; }
                    }
                    if ($hasProps) {
                        $nestedSubject = self::ldToQuads($val, $quads, $bn, $subject);
                        $quads[] = ['s' => $subject, 'p' => $pred, 'o' => ['@id' => $nestedSubject]];
                    }
                }
            }
        }

        return $subject;
    }

    // ── URDNA2015 canonicalization ───────────────────────────

    /**
     * URDNA2015: Canonicalize a set of quads by assigning deterministic
     * blank node labels. Returns sorted N-Quads string.
     */
    private static function urdna2015(array $quads): string
    {
        // 1. Identify all blank nodes and their quads
        $bnodeQuads = []; // bnode_label => [quad_indices]
        foreach ($quads as $i => $q) {
            if (str_starts_with($q['s'], '_:')) {
                $bnodeQuads[$q['s']][] = $i;
            }
            if (isset($q['o']['@id']) && str_starts_with($q['o']['@id'], '_:')) {
                $bnodeQuads[$q['o']['@id']][] = $i;
            }
        }

        if (empty($bnodeQuads)) {
            // No blank nodes — just serialize and sort
            return self::serializeAndSortQuads($quads, []);
        }

        // 2. Compute first-degree hash for each blank node
        $hashToNodes = [];
        $nodeHashes = [];
        foreach ($bnodeQuads as $bnode => $indices) {
            $nquadStrings = [];
            foreach ($indices as $idx) {
                $nquadStrings[] = self::serializeQuad($quads[$idx], [$bnode => '_:a']);
            }
            sort($nquadStrings);
            $hash = hash('sha256', implode('', $nquadStrings));
            $nodeHashes[$bnode] = $hash;
            $hashToNodes[$hash][] = $bnode;
        }

        // 3. Assign canonical labels
        $canonMap = [];
        $canonCounter = 0;

        // Sort hashes, process unique hashes first
        ksort($hashToNodes);
        foreach ($hashToNodes as $hash => $nodes) {
            if (count($nodes) === 1) {
                $canonMap[$nodes[0]] = '_:c14n' . ($canonCounter++);
                continue;
            }

            // Multiple nodes with same first-degree hash — use N-degree hash
            $hashPaths = [];
            foreach ($nodes as $node) {
                $pathHash = self::urdna2015NdegreeHash($quads, $bnodeQuads, $node, $nodeHashes, $canonMap);
                $hashPaths[] = [$pathHash, $node];
            }
            usort($hashPaths, fn($a, $b) => strcmp($a[0], $b[0]));
            foreach ($hashPaths as [$_, $node]) {
                if (!isset($canonMap[$node])) {
                    $canonMap[$node] = '_:c14n' . ($canonCounter++);
                }
            }
        }

        return self::serializeAndSortQuads($quads, $canonMap);
    }

    /**
     * Compute N-degree hash for URDNA2015 tie-breaking.
     * Simplified: uses connected component hash.
     */
    private static function urdna2015NdegreeHash(
        array $quads, array $bnodeQuads, string $node,
        array $nodeHashes, array $existing
    ): string {
        $visited = [$node => true];
        $data = $nodeHashes[$node] ?? '';

        foreach ($bnodeQuads[$node] ?? [] as $idx) {
            $q = $quads[$idx];
            $related = null;
            if (str_starts_with($q['s'], '_:') && $q['s'] !== $node) $related = $q['s'];
            if (isset($q['o']['@id']) && str_starts_with($q['o']['@id'], '_:') && $q['o']['@id'] !== $node) $related = $q['o']['@id'];

            if ($related !== null && !isset($visited[$related]) && !isset($existing[$related])) {
                $data .= ($nodeHashes[$related] ?? '') . $q['p'];
                $visited[$related] = true;
            }
        }

        return hash('sha256', $data);
    }

    /** Serialize a single quad as N-Quad string. */
    private static function serializeQuad(array $q, array $bnodeMap): string
    {
        $s = $q['s'];
        $s = $bnodeMap[$s] ?? $s;
        $s = str_starts_with($s, '_:') ? $s : "<$s>";

        $p = "<{$q['p']}>";

        $o = $q['o'];
        if (isset($o['@id'])) {
            $oid = $bnodeMap[$o['@id']] ?? $o['@id'];
            $oStr = str_starts_with($oid, '_:') ? $oid : "<$oid>";
        } else {
            $val = (string)($o['@value'] ?? '');
            // Escape N-Quads string: \, newline, carriage return, double quote
            $val = str_replace(['\\', "\n", "\r", '"'], ['\\\\', '\\n', '\\r', '\\"'], $val);
            $oStr = '"' . $val . '"';
            if (isset($o['@type']) && $o['@type'] !== 'http://www.w3.org/2001/XMLSchema#string') {
                $oStr .= '^^<' . $o['@type'] . '>';
            } elseif (isset($o['@language'])) {
                $oStr .= '@' . $o['@language'];
            }
        }

        return "$s $p $oStr .\n";
    }

    /** Serialize all quads with canonical bnode labels, sort, and join. */
    private static function serializeAndSortQuads(array $quads, array $canonMap): string
    {
        $lines = [];
        foreach ($quads as $q) {
            $lines[] = self::serializeQuad($q, $canonMap);
        }
        sort($lines);
        return implode('', $lines);
    }
}
