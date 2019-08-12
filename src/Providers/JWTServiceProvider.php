<?php

namespace TinyPixel\JWT\Providers;

use Firebase\JWT\JWT;
use TinyPixel\JWT\API;
use TinyPixel\JWT\JWTManager;
use TinyPixel\JWT\TokenResolver;
use Roots\Acorn\ServiceProvider;

/**
 * JSON Web Token service provider.
 *
 * @author   Kelly Mears <kelly@tinypixel.dev>
 * @license  MIT
 * @version  1.0.0
 * @since    1.0.0
 *
 * @package  JWT
 */
class JWTServiceProvider extends ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register() : void
    {
        $this->publishables = [
            'src'  => __DIR__ . '/../../publishes/config/auth.php',
            'dest' => $this->app->configPath('auth.php'),
        ];

        if ($this->isBootable()) {
            $this->jwtConfig = $this->app['config']->get('auth');

            $this->app->singleton('jwt', function ($app) {
                return new JWT();
            });

            $this->app->singleton('jwt.resolver', function ($app) {
                return new TokenResolver($app->make('jwt'), $this->jwtConfig);
            });

            $this->app->singleton('jwt.api', function ($app) {
                return new API($app->make('jwt.resolver'), $this->jwtConfig);
            });

            $this->app->singleton('jwt.manager', function ($app) {
                return new JWTManager($app, $this->jwtConfig);
            });
        }
    }

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot() : void
    {
        if ($this->isBootable()) {
            $this->app->make('jwt.manager')->init();
        } else {
            $this->publishes([$this->configSrc => $this->configDest], 'JWT');
        }
    }

    /**
     * Returns true if config is available.
     *
     * @return bool
     */
    public function isBootable() : bool
    {
        return file_exists($this->publishables['dest']);
    }
}
