<?php

namespace Foziluff\SocialAuth\Facades;

use Foziluff\SocialAuth\Services\SocialAuthService;
use Illuminate\Support\Facades\Facade;

/**
 * @method static array<string, mixed>|false verifyGoogle(string $token, ?string $clientId = null)
 * @method static array<string, mixed>|false verifyApple(string $token, ?string $clientId = null)
 *
 * @see SocialAuthService
 */
class SocialAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'foziluff.socialauth';
    }
}
