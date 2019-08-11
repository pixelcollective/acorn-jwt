<?php

namespace TinyPixel\AcornGlide\Providers;

use Roots\Acorn\ServiceProvider;
use TinyPixel\JWT\JWTManager;
use TinyPixel\JWT\TokenResolver;
use Firebase\JWT\JWT;

/**
 * JSON Web Token service provider.
 *
 * @author     Kelly Mears <kelly@tinypixel.dev>
 * @license    MIT
 * @version    1.0.0
 * @since      1.0.0
 *
 * @package    AcornGlide
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
            'dest' => $this->app->config_path('auth.php'),
        ];

        if ($this->isBootable()) {
            $this->jwtConfig = $this->app['config']->get('jwt');

            $this->app->singleton('jwt', function ($app) {
                return JWT::class;
            });

            $this->app->singleton('jwt.resolver', function ($app){
                return new TokenResolver(
                    $app->make('jwt'),
                    $this->jwtConfig['secret_key']
                );
            });

            $this->app->singleton('jwt.api', function ($app) {
                $api = new API(
                    $this->jwtConfig['namespace'],
                    $this->jwtConfig['version'],
                    $this->jwtConfig['cors_enabled']
                );

                return $api->init($this->jwtConfig['namespace']);
            });

            $this->app->singleton('jwt.manager', function ($app) {
                $resolver = $app->make('jwt.resolver');
                $api      = $app->make('jwt.api');

                return new JWTManager($resolver, $api);
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
        if(!$this->isBootable()) {
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
