<?php

namespace TinyPixel\JWT;

use Roots\Acorn\Application;
use Illuminate\Support\Collection;
use TinyPixel\JWT\Resolver;
use TinyPixel\JWT\API;

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
    public function __construct(Application $app, Resolver $resolver, API $api)
    {
        $this->app      = $app;
        $this->resolver = $resolver;
        $this->api      = $api;
    }

    /**
     * Initialize JWT Manager.
     *
     * @return void
     */
    public function init()
    {
        $this->setActions()
             ->setFilters();
    }

    /**
     * Set WordPress actions.
     *
     * @return JWTManager
     */
    protected function setActions()
    {
        add_action('rest_api_init', [$this->api, 'routes']);

        return $this;
    }

    /**
     * Set filters.
     *
     * @return JWT
     */
    public function setFilters() : JWT
    {
        add_filter('rest_api_init', [$this->resolver, 'cors']);

        add_filter('determine_current_user', [$this->resolver, 'setCurrentUser'], 10, 2);

        add_filter('rest_pre_dispatch', [$this->api, 'preDispatch'], 10, 2);

        return $this;
    }
}
