<?php

namespace Foziluff\SocialAuth\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array<string, mixed>|false verifyGoogle(string $token, ?string $clientId = null)
 * @method static array<string, mixed>|false verifyApple(string $token, ?string $clientId = null)
 *
 * @see \Foziluff\SocialAuth\Services\SocialAuthService
 */
class SocialAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'foziluff.socialauth';
    }
}
