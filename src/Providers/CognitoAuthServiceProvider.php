<?php

namespace PodPoint\LaravelCognitoAuth\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\Application;
use PodPoint\LaravelCognitoAuth\Auth\CognitoGuard;
use PodPoint\LaravelCognitoAuth\CognitoClient;
use PodPoint\LaravelCognitoAuth\Passwords\CognitoPasswordBrokerManager;

class CognitoAuthServiceProvider extends ServiceProvider
{
    /**
     * Register cognito authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../../config/cognito.php' => config_path('cognito.php'),
        ], 'config');

        $this->app->singleton(CognitoClient::class, function (Application $app) {
            $awsCognitoIdentityProvider = $app->make('aws')->createCognitoIdentityProvider();

            return new CognitoClient($awsCognitoIdentityProvider, config('cognito.app_client_id'), config('cognito.app_client_secret'), config('cognito.user_pool_id'));
        });

        $this->app['auth']->extend('cognito', function (Application $app, $name, array $config) {
            $guard = new CognitoGuard(
                $name,
                $client = $app->make(CognitoClient::class),
                $app['auth']->createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );

            $guard->setCookieJar($this->app['cookie']);
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    }
}
