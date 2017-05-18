<?php

namespace PodPoint\LaravelCognitoAuth\Auth;

use Illuminate\Auth\SessionGuard;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use PodPoint\LaravelCognitoAuth\CognitoClient;
use PodPoint\LaravelCognitoAuth\Exceptions\NoLocalUserException;
use PodPoint\LaravelCognitoAuth\Exceptions\PasswordResetRequiredException;
use Symfony\Component\HttpFoundation\Request;

class CognitoGuard extends SessionGuard implements StatefulGuard
{
    /**
     * An instance of the Cognito client.
     *
     * @var CognitoClient
     */
    protected $client;

    /**
     * Create a new authentication guard.
     *
     * @param string $name
     * @param CognitoClient $client
     * @param UserProvider $provider
     * @param Session $session
     * @param Request $request
     * @return void
     */
    public function __construct($name, CognitoClient $client, UserProvider $provider, Session $session, Request $request = null) {
        $this->client = $client;

        parent::__construct($name, $provider, $session, $request);
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        $response = $this->client->authenticate($credentials['email'], $credentials['password']);

        if ($response['ChallengeName'] == CognitoClient::NEW_PASSWORD_CHALLENGE) {
            $this->login($user);

            throw new PasswordResetRequiredException();
        }

        if ($response && is_null($user)) {
            $this->login($user);

            throw new NoLocalUserException();
        }

        return (bool) $response;
    }
}
