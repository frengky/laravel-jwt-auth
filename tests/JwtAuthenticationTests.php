<?php

namespace Frengky\JwtAuth\Tests;

use Frengky\JwtAuth\Tests\App\User;

use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

use Frengky\JwtAuth\JwtAuthentication;
use Frengky\JwtAuth\Facades\JwtAuth;

final class JwtAuthenticationTest extends TestCase
{
    protected function getEnvironmentSetUp($app) {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('jwt.algorithm', 'HS256');
        $app['config']->set('jwt.secret', Str::random(32));
        $app['config']->set('auth.guards.jwt', [
            'driver' => 'jwt',
            'provider' => 'users'
        ]);
        $app['config']->set('auth.providers.users.model', User::class);
    }

    protected function setUp(): void {
        parent::setUp();
        
        factory(User::class)->create();

        $router = $this->app['router'];

        $router->post('/login', 'Frengky\JwtAuth\Tests\App\Http\Controllers\AuthController@login');
        $router->get('/profile', 'Frengky\JwtAuth\Tests\App\Http\Controllers\AuthController@profile')->middleware('auth:jwt');
    }

    function test_access_profile_without_bearer_token() {
        $response = $this->json('GET', '/profile', [
            'Accept' => 'application/json'
        ]);
        $response->assertStatus(401);
        $response->assertExactJson(['message' => 'Unauthenticated.']);
    }
    
    public function test_login_and_access_profile_with_the_token() {
        $user = User::find(1);
        
        $response = $this->json('POST', '/login', [
            'email' => $user->email, 
            'password' => 'password'
        ]);
        $response->assertStatus(200);
        $response->assertSeeTextInOrder(['access_token', 'refresh_token']);

        $loginResponse = json_decode($response->content());
        $headers = [
            'Authorization' => 'Bearer ' . $loginResponse->access_token
        ];
        $response = $this->withHeaders($headers)->json('GET', '/profile', [
            'Accept' => 'application/json'
        ]);
        $response->assertStatus(200);
        $response->assertSeeText($user->name);
    }
}