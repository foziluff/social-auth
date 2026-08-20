<?php

namespace Foziluff\SocialAuth\Facades;

use Illuminate\Support\Facades\Facade;

class SocialAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'foziluff.socialauth';
    }
}
