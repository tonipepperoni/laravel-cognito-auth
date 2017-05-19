<?php

namespace PodPoint\LaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Foundation\Auth\ResetsPasswords as BaseResetsPasswords;
use PodPoint\LaravelCognitoAuth\CognitoClient;

trait ResetsPasswords
{
    use BaseResetsPasswords;

    /**
     * Reset the given user's password.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function reset(Request $request)
    {
        $this->validate($request, $this->rules(), $this->validationErrorMessages());

        $client = app()->make(CognitoClient::class);

        $user = $client->getUser($request->email);

        if ($user['UserStatus'] == CognitoClient::NEW_PASSWORD_CHALLENGE) {
            $login = $client->authenticate($request->email, $request->token);

            $response = $client->confirmPassword($request->email, $request->password, $login->get('Session'));
        } else {
            $response = $client->resetPassword($request->token, $request->email, $request->password);
        }

        return $response == Password::PASSWORD_RESET
                    ? $this->sendResetResponse($response)
                    : $this->sendResetFailedResponse($request, $response);
    }
}
