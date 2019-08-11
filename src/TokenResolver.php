<?php

namespace TinyPixel\JWT;

use Firebase\JWT\JWT;
use Illuminate\Support\Collection;

/**
 * Javascript Web Tokens
 *
 * @author   Kelly Mears <kelly@tinypixel.dev>
 * @license  MIT
 * @version  1.0.0
 * @since    1.0.0
 *
 * @package  JWT
 */
class TokenResolver
{
    /**
     * Cors
     *
     * @var bool
     */
    public $cors;

    /**
     * Secret key
     */
    public $secretKey;

    /**
     * Headers
     *
     * @var string
     */
    public $headers;

    /**
     * Encryption type
     *
     * @var string
     */
    public $encryptionType = 'HS256';

    /**
     * Valid for
     *
     * @var int
     */
    public $validFor = DAY_IN_SECONDS * 7;

    /**
     * ISS
     */
    public $iss;

    /**
     * Constructor.
     *
     * @param string $secretKey
     * @param bool   $cors
     */
    public function __construct(JWT $jwt, string $secretKey, bool $corsEnabled)
    {
        $this->JWT       = JWT::class;
        $this->secretKey = $secretKey;
        $this->cors      = $corsEnabled;
        $this->iss       = get_bloginfo('url');
        $this->errors    = Collection::make();
    }

    /**
     * Return a token
     *
     * @param timestamp $issued
     *
     * @return array
     */
    public function generateToken($issued)
    {
        return [
            'iss'  => $this->iss,
            'iat'  => $issued,
            'nbf'  => $issued,
            'exp'  => $this->validFor + $issued,
            'data' => ['user' => ['id' => $user->data->ID]],
        ];
    }

    /**
     * Authenticate user validity for response.
     *
     * @param (int|bool) $user
     *
     * @return (int|bool)
     */
    public function setCurrentUser($user)
    {
        if(!$validUri = strpos($_SERVER['REQUEST_URI'], \rest_get_url_prefix())) {
            return $user;
        }

        if (strpos($_SERVER['REQUEST_URI'], 'token/validate') > 0) {
            return $user;
        }

        $token = $this->validateToken(false);

        if (\is_wp_error($token)) {
            if ($token->get_error_code() != 'jwt_no_auth_header') {
                $this->errors->put($token->get_error_code());
            }

            return $user;
        }

        return $token->data->user->id;
    }

    /**
     * Validate token format.
     *
     * @return mixed
     */
    public function validateTokenFormat()
    {
        list($token) = sscanf($this->authHeader, 'Bearer %s');

        if (!$token) {
            return false;
        }

        return $token;
    }

    /**
     * Validate request headers.
     *
     * @return mixed
     */
    public function validateHeaders()
    {
        $auth = isset($_SERVER['HTTP_AUTHORIZATION']) ?
                $_SERVER['HTTP_AUTHORIZATION'] :
                false;

        if (!$auth) {
            $auth = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ?
                    $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] :
                    false;
        }

        return $auth ? $auth : false;
    }

    /**
     * Decrypt token
     *
     * @return mixed
     */
    public function decryptToken()
    {
        $decryptedToken = $this->JWT::decode(
            $this->token,
            $this->secretKey,
            [$this->encryptionType]
        );

        if ($decryptedToken->iss != get_bloginfo('url')) {
            return false;
        }

        if (!isset($decryptedToken->data->user->id)) {
            return false;
        }

        return !$output ? $decryptedToken : [
            'code' => 'jwt_valid_token',
            'data' => ['status' => 200],
        ];
    }
}

