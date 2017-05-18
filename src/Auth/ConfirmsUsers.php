<?php

namespace PodPoint\LaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Foundation\Auth\RedirectsUsers;
use PodPoint\LaravelCognitoAuth\CognitoClient;

trait ConfirmsUsers
{
    use RedirectsUsers;

    /**
     * Display the confirm view for the given code.
     *
     * If no code is present, display the link request form.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string|null  $code
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     */
    public function showConfirmForm(Request $request, $code = null)
    {
        return view('auth.confirm')->with(
            ['code' => $code, 'email' => $request->email]
        );
    }

    /**
     * Confirm the given user's email.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function confirm(Request $request)
    {
        $this->validate($request, $this->rules(), $this->validationErrorMessages());

        $response = app()->make(CognitoClient::class)->confirmRegistration($request->code, $request->email);

        return $response == CognitoClient::USER_CONFIRMED
                    ? $this->sendResetResponse($response)
                    : $this->sendResetFailedResponse($request, $response);
    }

    /**
     * Get the email confirmation validation rules.
     *
     * @return array
     */
    protected function rules()
    {
        return [
            'code' => 'required',
            'email' => 'required|email',
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
    protected function sendResetResponse($response)
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
    protected function sendResetFailedResponse(Request $request, $response)
    {
        return redirect()->back()
                    ->withInput($request->only('code'))
                    ->withErrors(['code' => trans($response)]);
    }
}
