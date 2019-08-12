<?php

use function Roots\env;

/*
|--------------------------------------------------------------------------
| JSON Web Tokens
|--------------------------------------------------------------------------
|
| JSON Web Token (JWT) is an open standard (RFC 7519) that defines a
| compact and self-contained way for securely transmitting information
| between parties as a JSON object. This information can be verified
| and trusted because it is digitally signed. JWTs can be signed using
| a secret (with the HMAC algorithm) or a public/private key pair using
| RSA or ECDSA.
|
*/

return [

    /*
    |--------------------------------------------------------------------------
    | Site URL
    |--------------------------------------------------------------------------
    |
    | Domain of site providing JWT services.
    |
    */

    'site_url' => get_bloginfo('url'),

    /*
    |--------------------------------------------------------------------------
    | WordPress Rest API
    |--------------------------------------------------------------------------
    |
    | WordPress REST Namespace
    |
    */

    'api' => [
        'namespace' => 'jwt-auth',
        'version'   => 'v1',
    ],

    /*
    |--------------------------------------------------------------------------
    | Application JWT Secret Key
    |--------------------------------------------------------------------------
    |
    | Some utilities you may consider when generating your application's secret
    | key:
    |
    | @link https://roots.io/salts.html
    | @link https://github.com/anders/pwgen
    |
    */

    'secret_key'  => env('JWT_SECRET_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Encryption type
    |--------------------------------------------------------------------------
    |
    | Set algorithm to use when encrypting and decrypting tokens. When using
    | RS256 you will also need to set a private and public key. Default: HS256.
    |
    */

    'encryption' => [
        'type'        => 'HS256',
        'private_key' => env('JWT_OPENSSL_PRIVATE_KEY', null),
        'public_key'  => env('JWT_OPENSSL_PUBLIC_KEY', null),
    ],

    /*
    |--------------------------------------------------------------------------
    | Token expiration
    |--------------------------------------------------------------------------
    |
    | Here you may customize the period of time a token remains valid.
    |
    */

    'expiration' => DAY_IN_SECONDS * 7,

    /*
    |--------------------------------------------------------------------------
    | Enable CORS
    |--------------------------------------------------------------------------
    |
    | Cross-Origin Resource Sharing (CORS) is a mechanism that uses
    | additional HTTP headers to tell a browser to let a web application
    | running at one origin (domain) have permission to access selected
    | resources from a server at a different origin. A web application
    | executes a cross-origin HTTP request when it requests a resource that
    | has a different origin (domain, protocol, or port) than its own origin.
    |
    */

    'cors_enabled' => env('JWT_CORS_ENABLED', false),

];
