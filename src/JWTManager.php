<?php

namespace TinyPixel\JWT;

use function \add_action;
use function \add_filter;
use Roots\Acorn\Application;
use Illuminate\Support\Collection;
use TinyPixel\JWT\Resolver;
use TinyPixel\JWT\API;

/**
 * JSON Web Token Manager
 *
 * @author   Kelly Mears <kelly@tinypixel.dev>
 * @license  MIT
 * @version  1.0.0
 * @since    1.0.0
 *
 * @package  JWT
 */
class JWTManager
{
    /**
     * Container.
     *
     * @var Application
     */
    protected $app;

    /**
     * Filters
     *
     * @var Collection
     */
    protected $filters;

    /**
     * Actions
     *
     * @var Collection
     */
    protected $actions;

    /**
     * Constructor.
     *
     * @param Application $app
     * @param Resolver    $resolver
     * @param API         $api
     */
    public function __construct(Application $app, array $config)
    {
        $this->app    = $app;
        $this->config = $config;

        $this->resolver = $app->make('jwt.resolver');
        $this->api      = $app->make('jwt.api');
    }

    /**
     * Initialize JWT Manager.
     *
     * @return void
     */
    public function init() : void
    {
        $this->setActions();
        $this->setFilters();
    }

    /**
     * Set WordPress actions.
     *
     * @return void
     */
    protected function setActions() : void
    {
        add_action('rest_api_init', function () {
            $this->api->routes();
        });
    }

    /**
     * Set filters.
     *
     * @return void
     */
    public function setFilters() : void
    {
        add_filter('rest_api_init', function () {
            $this->api->cors();
        });

        add_filter('determine_current_user', function () {
            $this->resolver->setCurrentUser();
        }, 10, 2);

        add_filter('rest_pre_dispatch', function ($response) {
            $this->api->preDispatch($response);
        }, 10, 2);
    }
}
