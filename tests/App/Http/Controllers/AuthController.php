<?php

namespace Frengky\JwtAuth\Tests\App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

use Frengky\JwtAuth\Facades\JwtAuth;
use Frengky\JwtAuth\Tests\App\User;

class AuthController extends Controller
{
    public function login(Request $request) {
        $email = $request->input('email');
        $password = $request->input('password');

        $user = User::where('email', $email)->first();
        if (empty($user) || !Hash::check($password, $user->password)) {
            Log::debug(sprintf('Login failed for [%s] with password [%s]', $user->email, $password));
            return response()->json(['error' => 'Invalid credentials'], 422);
        }

        auth()->login($user);

        $accessToken = JwtAuth::createToken($user, [], 3600);
        $refreshToken = JwtAuth::createToken($user, [], 3600*24*7);

        Log::debug(sprintf('Login successful for [%s] with password [%s]', $user->email, $password));

        return response()->json([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken
        ]);
    }

    public function profile(Request $request) {
        $user = auth()->user();
        Log::debug(sprintf('Showing profile for [%s]', $user->email));

        return response()->json($user->toArray());
    }
}