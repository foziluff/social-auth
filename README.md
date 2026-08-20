# Secure Social Auth for Laravel

A highly optimized, zero-heavy-dependency Laravel package for validating Google and Apple JWT (JSON Web Tokens) securely on your backend.

This package was built to completely eliminate the need for bloated SDKs (like `google/apiclient`) when your only goal is to verify a user's sign-in token. 

## Key Features

- **Security First**: Automatically protects against [Confused Deputy Attacks](https://en.wikipedia.org/wiki/Confused_deputy_problem) by strictly enforcing `aud` (Audience/Client ID) validation.
- **Blazing Fast**: Converts Apple and Google JWKs (JSON Web Keys) into native PEM certificates and caches them using an $O(1)$ lookup hash map.
- **DoS / Cache Stampede Protection**: Uses atomic caching locks (`Cache::add`) with a 60-second cooldown to ensure your server never spams Google/Apple APIs under high load.
- **Fail-Safe Mode**: If Google or Apple's JWK servers go down, the package will automatically continue using the stale cache to keep your users logging in without interruption.
- **Lightweight**: Uses only Laravel's built-in `Illuminate\Http` and `Illuminate\Cache`.

## Installation

You can install the package via composer:

```bash
composer require foziluff/social-auth
```

## Usage

Use the `SocialAuth` facade to verify tokens securely.

### Verifying a Google Token

```php
use Foziluff\SocialAuth\Facades\SocialAuth;

$googleToken = '...';
$googleClientId = 'your-google-client-id.apps.googleusercontent.com';

$payload = SocialAuth::verifyGoogle($googleToken, $googleClientId);

if ($payload) {
    // Verification successful!
    $googleUserId = $payload['sub'];
    $email = $payload['email'] ?? null;
    $name = $payload['name'] ?? null;
} else {
    // Verification failed (invalid signature, expired, or wrong client ID)
}
```

### Verifying an Apple Token

```php
use Foziluff\SocialAuth\Facades\SocialAuth;

$appleToken = '...';
$appleClientId = 'com.yourcompany.app';

$payload = SocialAuth::verifyApple($appleToken, $appleClientId);

if ($payload) {
    // Verification successful!
    $appleUserId = $payload['sub'];
    $email = $payload['email'] ?? null;
} else {
    // Verification failed
}
```

## How It Works (Under the Hood)

When you call `verifyGoogle` or `verifyApple`, the package:
1. Validates the JWT structure and ensures it hasn't expired (`exp` claim).
2. Verifies the issuer (`iss` claim) to ensure the token actually came from Google/Apple.
3. **Crucial:** Validates the `aud` (Audience) claim against your specific `ClientId`. This prevents attackers from generating a valid Google token using *their* app and passing it to *your* backend.
4. Checks Laravel's Cache for the specific PEM certificate matching the token's `kid` (Key ID).
5. If the key is missing or new, it fetches the latest keys via HTTP, converts the raw RSA Modulus and Exponent into a native X.509 PEM string, and caches them for 30 days.
6. Verifies the RSA SHA-256 signature natively using PHP's `openssl_verify`.

## License

The MIT License (MIT).
