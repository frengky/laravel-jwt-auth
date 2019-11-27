<?php

namespace Frengky\JwtAuth\Tests;

use Illuminate\Support\Facades\Log;
use Monolog\Handler\StreamHandler;

abstract class TestCase extends \Orchestra\Testbench\TestCase
{
    /**
     * Setup the test environment
     */
    protected function setUp(): void
    {
        parent::setUp();
        Log::pushHandler(new StreamHandler("php://stdout"));

        $this->loadMigrationsFrom(
            realpath(__DIR__.'/database/migrations')
        );
        $this->withFactories(
            realpath(__DIR__.'/database/factories')
        );

        $this->artisan('migrate', ['--database' => 'testing']);
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     *
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    /**
     * Define package service provider
     *
     * @param \Illuminate\Foundation\Application $app
     * @return array
     */
    protected function getPackageProviders($app)
    {
        return [
            \Frengky\JwtAuth\ServiceProvider::class
        ];
    }

    /**
     * Get application timezone.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return string|null
     */
    protected function getApplicationTimezone($app)
    {
        return 'Asia/Jakarta';
    }    
}