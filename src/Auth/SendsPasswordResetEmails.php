<?php

namespace PodPoint\LaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Foundation\Auth\SendsPasswordResetEmails as BaseSendsPasswordResetEmails;
use PodPoint\LaravelCognitoAuth\CognitoClient;

trait SendsPasswordResetEmails
{
    use BaseSendsPasswordResetEmails;

    /**
     * Send a reset link to the given user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function sendResetLinkEmail(Request $request)
    {
        $this->validateEmail($request);

        $response = app()->make(CognitoClient::class)->sendResetLink($request->email);

        return $response == Password::RESET_LINK_SENT
                    ? $this->sendResetLinkResponse($response)
                    : $this->sendResetLinkFailedResponse($request, $response);
    }
}
