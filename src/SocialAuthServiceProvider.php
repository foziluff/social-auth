<?php

namespace Foziluff\SocialAuth;

use Foziluff\SocialAuth\Services\SocialAuthService;
use Illuminate\Support\ServiceProvider;

class SocialAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton('foziluff.socialauth', function ($app) {
            return new SocialAuthService;
        });
    }

    public function boot(): void
    {
        //
    }
}
