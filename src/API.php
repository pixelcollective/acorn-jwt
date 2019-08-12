<?php

namespace TinyPixel\JWT;

use function \is_wp_error;
use function \wp_authenticate;
use function \register_rest_route;
use Roots\Acorn\Application;
use Illuminate\Support\Collection;
use TinyPixel\JWT\Resolver;

/**
 * JSON Web Token API handler
 *
 * @author   Kelly Mears <kelly@tinypixel.dev>
 * @license  MIT
 * @version  1.0.0
 * @since    1.0.0
 *
 * @package  JWT
 */
class API
{
    /**
     * Construct.
     */
    public function __construct(TokenResolver $resolver, array $config)
    {
        $this->resolver = $resolver;

        $this->api = [
            'namespace' => $config['api']['namespace'],
            'version'   => $config['api']['version'],
        ];
    }

    /**
     * Return namespaced, versioned API route.
     *
     * @return string
     */
    public function getApiRoute()
    {
        return "{$this->api['namespace']}/{$this->api['version']}";
    }

    /**
     * Add the endpoints to the API
     *
     * @return void
     *
     * @uses \register_rest_route
     */
    public function routes()
    {
        \register_rest_route($this->getApiRoute(), 'token', [
            'methods'  => 'POST',
            'callback' => [$this, 'requestToken'],
        ]);

        \register_rest_route($this->getApiRoute(), 'token/validate', [
            'methods'  => 'POST',
            'callback' => [$this, 'validateToken'],
        ]);
    }

    /**
     * Authenticate the request body's auth parameters
     * and generate a JWT
     *
     * @param $request
     *
     * @return mixed
     *
     * @uses \wp_authenticate
     * @uses \is_wp_error
     */
    public function requestToken($request)
    {
        if (!$this->resolver->secretKey) {
            return false;
        }

        $user = \wp_authenticate(
            $request->get_param('username'),
            $request->get_param('password')
        );

        if(\is_wp_error($user)) {
            return false;
        }

        $token = $this->resolver->generateToken(time(), $user);

        return [
            'token'             => $this->resolver->generateToken(time(), $user),
            'user_email'        => $user->data->user_email,
            'user_nicename'     => $user->data->user_nicename,
            'user_display_name' => $user->data->display_name,
        ];
    }

    /**
     * Validate user and decode tokens.
     *
     * @param  bool $output
     *
     * @return mixed
     */
    public function validateToken($output = true)
    {
        $this->authHeader = $this->resolver->validateHeaders();
        $this->token      = $this->resolver->validateTokenFormat();

        return $this->resolver->decryptToken(true);
    }

    /**
     * Add CORS support to the request if configured.
     *
     * @return void
     */
    public function cors()
    {
        if (isset($this->cors)) {
            $this->headers = 'Access-Control-Allow-Headers, Content-Type, Authorization';
        }
    }

    /**
     * Sends back error if thrown.
     *
     * @param  $request
     *
     * @return $request
     */
    public function preDispatch($request)
    {
        if ($err = $this->hasErrors()) {
            return $err;
        }

        if (isset($this->headers)) {
            header($this->headers);
        }

        return $request;
    }

    /**
     * Request has an error.
     *
     * @param  bool $err
     *
     * @return mixed array of errors | false if no errors
     */
    public function hasErrors($errors = [])
    {
        $this->resolver->errors->each(function ($err) use (& $errors) {
            $errors[] = $err;
        });

        return empty($errors) ? false : $errors;
    }
}
