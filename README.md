# Laravel Cognito Auth
AWS Cognito Auth driver for Laravel

## Installation

Add the service provider in `config/app.php`:

```
PodPoint\LaravelCognitoAuth\Providers\CognitoAuthServiceProvider::class
```

Update the driver in `auth.php`:

```
'driver' => 'cognito',
```

Publish the config file:

```
php artisan vendor:publish --provider="PodPoint\LaravelCognitoAuth\Providers\CognitoAuthServiceProvider"
```

Add the following to your `.env` file:

```
AWS_KEY=
AWS_SECRET=
AWS_REGION=
AWS_COGNITO_CLIENT_ID=
AWS_COGNITO_CLIENT_SECRET=
AWS_COGNITO_USER_POOL_ID=
```

## Usage

You can either use the provided Laravel Auth style traits which provide a boilerplate for a standard Laravel Auth workflow:

* `PodPoint\LaravelCognitoAuth\Auth\AuthenticatesUsers`
* `PodPoint\LaravelCognitoAuth\Auth\RegistersUsers`
* `PodPoint\LaravelCognitoAuth\Auth\ResetsPasswords`
* `PodPoint\LaravelCognitoAuth\Auth\SendsPasswordResetEmails`

Or you can use the `CognitoClient` directly.

#### Registration Flows

```
register($username, $password, array $attributes = [])
```
This will register a user with a given user/password and set their email address as verified. The user will immediatly be able to log in with the supplied credentials.

```
inviteUser($username, array $attributes = [])
```
This will register a user with the given email address and mark them as `NEW_PASSWORD_REQUIRED`. They will also be sent an email asking them to reset their password via the existing password reset workflow. Once this password is set the user will be able to log in.
