<?php

namespace Frengky\JwtAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;

class JWTGuard implements Guard
{
    /**
     * The currently authenticated user.
     *
     * @var Authenticatable
     */
    protected $user;

    /**
     * The user provider implementation.
     *
     * @var UserProvider
     */
    protected $provider;

    /**
     * @var JwtAuthentication
     */
    protected $jwt;

    public function __construct(UserProvider $provider, JwtAuthentication $jwt) {
        $this->provider = $provider;
        $this->jwt = $jwt;
    }
    
    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check() {
        return ! is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest() {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return Authenticatable|null
     */
    public function user()  {
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        if ($this->jwt->hasValidToken()) {
            $user = $this->provider->retrieveById($this->jwt->getToken()->getClaim('sub'));
        }

        return $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id() {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = []) {
        $user = $this->provider->retrieveByCredentials($credentials);
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Set the current user.
     *
     * @param  Authenticatable  $user
     * @return $this
     */
    public function setUser(Authenticatable $user) {
        $this->user = $user;

        return $this;
    }
}