<?php

namespace PodPoint\LaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Foundation\Auth\RedirectsUsers;
use PodPoint\LaravelCognitoAuth\CognitoClient;

trait ConfirmsPasswords
{
    use RedirectsUsers;

    /**
     * Display the confirm view for the given token.
     *
     * If no token is present, display the link request form.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string|null  $token
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     */
    public function showConfirmPasswordForm(Request $request, $token = null)
    {
        return view('auth.confirm.password')->with(
            ['token' => $token, 'email' => $request->email]
        );
    }

    /**
     * Confirm the given user's email.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function confirmPassword(Request $request)
    {
        $this->validate($request, $this->rules(), $this->validationErrorMessages());

        $response = $this->client->authenticate($request->email, $request->token);

        if ($response['ChallengeName'] == CognitoClient::NEW_PASSWORD_CHALLENGE) {
            $response = app()->make(CognitoClient::class)->confirmPassword($request->password, $request->email);
        }

        return $response == Password::PASSWORD_RESET
                    ? $this->sendConfirmPasswordResponse($response)
                    : $this->sendConfirmPasswordFailedResponse($request, $response);
    }

    /**
     * Get the email confirmation validation rules.
     *
     * @return array
     */
    protected function rules()
    {
        return [
            'token' => 'required',
            'email' => 'required',
            'password' => 'required|confirmed|min:6',
        ];
    }

    /**
     * Get the email confirmation validation error messages.
     *
     * @return array
     */
    protected function validationErrorMessages()
    {
        return [];
    }

    /**
     * Get the response for a successful email confirm.
     *
     * @param  string  $response
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function sendConfirmPasswordResponse($response)
    {
        return redirect($this->redirectPath())
                            ->with('status', trans($response));
    }

    /**
     * Get the response for a failed email confirm.
     *
     * @param  \Illuminate\Http\Request
     * @param  string  $response
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function sendConfirmPasswordFailedResponse(Request $request, $response)
    {
        return redirect()->back()
                    ->withInput($request->only('code'))
                    ->withErrors(['code' => trans($response)]);
    }
}
