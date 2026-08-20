<?php

namespace Foziluff\SocialAuth\Services;

use Foziluff\SocialAuth\Support\JwkToPem;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

class SocialAuthService
{
    private const GOOGLE_CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

    private const APPLE_CERTS_URL = 'https://appleid.apple.com/auth/keys';

    private const CACHE_TTL = 30 * 24 * 60 * 60;

    private const MAX_TOKEN_LENGTH = 8192;

    private const LEEWAY = 60;

    /**
     * @return array<string, mixed>|false
     */
    public function verifyGoogle(string $token, string $clientId): array|false
    {
        return $this->verify(
            $token,
            self::GOOGLE_CERTS_URL,
            'foziluff_google_jwks',
            ['accounts.google.com', 'https://accounts.google.com'],
            $clientId
        );
    }

    /**
     * @return array<string, mixed>|false
     */
    public function verifyApple(string $token, string $clientId): array|false
    {
        return $this->verify(
            $token,
            self::APPLE_CERTS_URL,
            'foziluff_apple_jwks',
            ['https://appleid.apple.com'],
            $clientId
        );
    }

    /**
     * @param  array<int, string>  $validIssuers
     * @return array<string, mixed>|false
     */
    private function verify(string $token, string $certsUrl, string $cacheKey, array $validIssuers, string $clientId): array|false
    {
        if (strlen($token) > self::MAX_TOKEN_LENGTH) {
            return false;
        }

        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return false;
            }

            [$headerB64, $payloadB64, $signatureB64] = $parts;

            $header = $this->decodePart($headerB64);
            $payload = $this->decodePart($payloadB64);

            if (! $this->isValidHeader($header) || ! $this->isValidPayload($payload, $validIssuers, $clientId)) {
                return false;
            }

            $pem = $this->getMatchingPem($certsUrl, $cacheKey, $header['kid']);

            if ($pem && $this->verifySignature($headerB64, $payloadB64, $signatureB64, $pem)) {
                return $payload;
            }

            if (! $pem) {
                $pem = $this->getMatchingPem($certsUrl, $cacheKey, $header['kid'], true);

                if ($pem && $this->verifySignature($headerB64, $payloadB64, $signatureB64, $pem)) {
                    return $payload;
                }
            }

            return false;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function decodePart(string $b64): ?array
    {
        $decoded = $this->base64UrlDecode($b64);

        return json_decode($decoded, true);
    }

    /**
     * @param  array<string, mixed>|null  $header
     */
    private function isValidHeader(?array $header): bool
    {
        if (! $header || empty($header['kid']) || empty($header['alg'])) {
            return false;
        }

        return $header['alg'] === 'RS256';
    }

    /**
     * @param  array<string, mixed>|null  $payload
     * @param  array<int, string>  $validIssuers
     */
    private function isValidPayload(?array $payload, array $validIssuers, string $clientId): bool
    {
        if (! $payload) {
            return false;
        }

        if (empty($payload['exp']) || ($payload['exp'] + self::LEEWAY) < time()) {
            return false;
        }

        if (empty($payload['iss']) || ! in_array($payload['iss'], $validIssuers, true)) {
            return false;
        }

        $aud = $payload['aud'] ?? '';
        $audiences = is_array($aud) ? $aud : [$aud];
        if (! in_array($clientId, $audiences, true)) {
            return false;
        }

        return true;
    }

    private function getMatchingPem(string $certsUrl, string $cacheKey, string $kid, bool $forceRefresh = false): ?string
    {
        $pems = Cache::get($cacheKey);

        if ($pems === null || $forceRefresh) {
            $lockKey = $cacheKey.'_refresh_lock';

            if ($pems === null || Cache::add($lockKey, true, 60)) {
                try {
                    $newPems = $this->fetchPems($certsUrl);
                    Cache::put($cacheKey, $newPems, self::CACHE_TTL);
                    $pems = $newPems;
                } catch (Throwable $e) {
                    if ($pems === null) {
                        return null;
                    }
                }
            }
        }

        return is_array($pems) ? ($pems[$kid] ?? null) : null;
    }

    /**
     * @return array<string, string>
     */
    private function fetchPems(string $certsUrl): array
    {
        $response = Http::timeout(5)->retry(3, 100)->get($certsUrl);

        if (! $response->successful()) {
            throw new \RuntimeException("Failed to fetch JWKS from {$certsUrl}");
        }

        $keys = $response->json('keys');

        if (! is_array($keys) || empty($keys)) {
            throw new \RuntimeException("Received empty JWKS from {$certsUrl}");
        }

        $pems = [];
        foreach ($keys as $key) {
            if (isset($key['kid'])) {
                $pem = JwkToPem::convert($key);
                if ($pem) {
                    $pems[$key['kid']] = $pem;
                }
            }
        }

        if (empty($pems)) {
            throw new \RuntimeException("No valid keys could be converted to PEM from {$certsUrl}");
        }

        return $pems;
    }

    private function verifySignature(string $headerB64, string $payloadB64, string $signatureB64, string $pem): bool
    {
        $dataToVerify = $headerB64.'.'.$payloadB64;
        $signature = $this->base64UrlDecode($signatureB64);

        return openssl_verify($dataToVerify, $signature, $pem, OPENSSL_ALGO_SHA256) === 1;
    }

    private function base64UrlDecode(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }
}
