<?php

namespace Frengky\JwtAuth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Builder;

class ServiceProvider extends BaseServiceProvider 
{
    /**
     * Register any application authentication / authorization services.
     *
     * @return void
     */
    public function boot() {
        $this->loadMigrationsFrom(realpath(__DIR__.'/../database/migrations'));

        $this->publishes([
            realpath(__DIR__.'/../config/jwt.php') => config_path('jwt.php')
        ], 'config');

        Auth::extend('jwt', function ($app, $name, array $config) {
            return new JwtGuard(Auth::createUserProvider($config['provider']), $app->make(JwtAuthentication::class));
        });
    }

    /**
     * Register the application services
     */
    public function register() {
        $this->mergeConfigFrom(realpath(__DIR__.'/../config/jwt.php'), 'jwt');

        $this->app->singleton(JwtAuthentication::class, function($app) {
            return new JwtAuthentication($app['config']['jwt']);
        });
    }
}