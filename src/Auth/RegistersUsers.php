<?php

namespace PodPoint\LaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\RegistersUsers as BaseSendsRegistersUsers;
use PodPoint\LaravelCognitoAuth\CognitoClient;

trait RegistersUsers
{
    use BaseSendsRegistersUsers;

    /**
     * Handle a registration request for the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $this->validator($request->all())->validate();

        app()->make(CognitoClient::class)->register($request->email, $request->password);

        event(new Registered($user = $this->create($request->all())));

        return $this->registered($request, $user)
                        ?: redirect($this->redirectPath());
    }
}
