<?php

namespace Frengky\JwtAuth\Facades;

use Illuminate\Support\Facades\Facade;

use Frengky\JwtAuth\JwtAuthentication;

class JwtAuth extends Facade
{
    protected static function getFacadeAccessor() {
        return JwtAuthentication::class;
    }
}