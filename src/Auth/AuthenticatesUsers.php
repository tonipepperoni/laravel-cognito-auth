<?php

namespace PodPoint\LaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\AuthenticatesUsers as BaseAuthenticatesUsers;
use PodPoint\LaravelCognitoAuth\Exceptions\NoLocalUserException;
use PodPoint\LaravelCognitoAuth\Exceptions\PasswordResetRequiredException;

trait AuthenticatesUsers
{
    use BaseAuthenticatesUsers;

    /**
     * Attempt to log the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function attemptLogin(Request $request)
    {
        try {
            $response = $this->guard()->attempt($this->credentials($request), $request->has('remember'));
        } catch (NoLocalUserException $e) {
            $response = $this->createLocalUser($this->credentials($request));
        } catch (PasswordResetRequiredException $e) {
            session(['forceChangePassword' => true]);
            return true;
        }

        return $response;
    }

    /**
     * Create a local user if one does not exist.
     *
     * @param  array  $credentials
     * @return mixed
     */
    protected function createLocalUser($credentials)
    {
        return true;
    }
}
