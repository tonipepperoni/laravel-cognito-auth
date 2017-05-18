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

        $response = app()->make(CognitoClient::class)->resetPassword($request->token, $request->email, $request->password);

        return $response == Password::PASSWORD_RESET
                    ? $this->sendResetResponse($response)
                    : $this->sendResetFailedResponse($request, $response);
    }
}
