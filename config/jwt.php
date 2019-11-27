<?php

return [

    'issuer' => env('JWT_ISSUER'),
    
    'expired' => 3600,
    
    /**
     * HMAC = HS256, HS384, HS512
     * ECDSA = ES256, ES384, ES512
     * RSA = RS256, RS384, RS512
     */
    'algorithm' => env('JWT_ALGORITHM', 'HS256'),

    /**
     * HMAC
     */
    'secret' => env('JWT_SECRET'),

    /**
     * ECDSA/RSA
     */
    'private' => env('JWT_PRIVATE_KEY'),
    'public' => env('JWT_PUBLIC_KEY'),
    'passphrase' => env('JWT_PASSPHRASE'),

];