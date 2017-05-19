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

You can either use the provided Laravel Auth style traits

`PodPoint\LaravelCognitoAuth\Auth\AuthenticatesUsers`
`PodPoint\LaravelCognitoAuth\Auth\RegistersUsers`
`PodPoint\LaravelCognitoAuth\Auth\ResetsPasswords`
`PodPoint\LaravelCognitoAuth\Auth\SendsPasswordResetEmails`

Or you can use the `CognitoClient` directly.
