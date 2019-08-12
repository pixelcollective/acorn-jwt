<?php

namespace TinyPixel\JWT;

use function \is_wp_error;
use Firebase\JWT\JWT;
use Illuminate\Support\Collection;

/**
 * JSON Web Token Resolver
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
    public $encryptionType;

    /**
     * Valid for
     *
     * @var int
     */
    public $validFor;

    /**
     * ISS
     */
    public $iss;

    /**
     * Constructor.
     *
     * @param \Firebase\JWT\JWT $jwt
     * @param array             $config
     */
    public function __construct(JWT $jwt, array $config)
    {
        $this->configureTokenHandling($config);

        $this->JWT    = JWT::class;
        $this->errors = Collection::make();
    }

    /**
     * Configures token handling.
     *
     * @param array $config
     */
    public function configureTokenHandling($config)
    {
        $this->secretKey      = $config['secret_key'];
        $this->iss            = $config['site_url'];
        $this->encryptionType = $config['encryption']['type'];
        $this->validFor       = $config['token_expiration'];

        if ($this->encryptionType == 'RS256') {
            $this->encryptionPrivateKey = $config['encryption']['private_key'];
            $this->encryptionPublicKey  = $config['encryption']['public_key'];
        }
    }

    /**
     * Returns a newly encoded token.
     *
     * @param int       $issued
     * @param \WP_User  $user
     *
     * @return string
     */
    public function generateToken(int $issued, \WP_User $user) : string
    {
        return JWT::encode([
            'iss'  => $this->iss,
            'iat'  => $issued,
            'nbf'  => $issued,
            'exp'  => $this->validFor + $issued,
            'data' => $this->formatUserResponseObject($user),
        ], $this->getEncryptionSecret());

    }

    /**
     * Format user object in preparation for response.
     *
     * @return array
     */
    protected function formatUserResponseObject($user) : array
    {
        return ['user' => ['id' => $user->data->ID]];
    }

    /**
     * If request is valid set user accordingly.
     *
     * @param \WP_User $user
     *
     * @return mixed
     * @uses   \is_wp_error
     */
    public function setCurrentUser(\WP_User $user)
    {
        if(!$validUri = strpos($_SERVER['REQUEST_URI'], \rest_get_url_prefix())) {
            return $this->user = $user;
        }

        if (strpos($_SERVER['REQUEST_URI'], 'token/validate') > 0) {
            return $this->user = $user;
        }

        $token = $this->validateTokenFormat();

        if ($token==false) {
            return;
        }

        if (\is_wp_error($token)) {
            if ($token->get_error_code() != 'jwt_no_auth_header') {
                $this->errors->put($token->get_error_code());
            }

            return $this->user;
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
        list($this->token) = sscanf($this->validateHeaders(), 'Bearer %s');

        return isset($tthis->token) ? $this->token : false;
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

        return isset($auth) ? $auth : false;
    }

    /**
     * Decrypt token
     *
     * @return mixed
     */
    public function decryptToken($output)
    {
        /**
         * Decrypt the token
         */
        $decryptedToken = $this->JWT::decode(
            $this->token,
            $this->getEncryptionSecret(),
            [$this->encryptionType]
        );

        /**
         * Bail early if decrypted token does not originate expectedly,
         * or if the token does not match the user making the request
         */
        if ($decryptedToken->iss != $this->iss ||
            !isset($decryptedToken->data->user->id)) {
            return false;
        }

        /**
         * Otherwise return the REST response
         */
        return [
            'code'  => 'jwt_valid_token',
            'data'  => ['status' => 200],
            'token' => $decryptedToken,
        ];
    }

    /**
     * Get encryption secret.
     *
     * @return string
     */
    protected function getEncryptionSecret()
    {
        return $this->encryptionType=='RS256' && isset($this->encryptionPrivateKey)
            ? $this->encryptionPrivateKey : $this->secretKey;
    }
}

