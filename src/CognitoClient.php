<?php

namespace PodPoint\LaravelCognitoAuth;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

class CognitoClient
{
    /**
     * Constant representing the user needs a new password.
     *
     * @var string
     */
    const NEW_PASSWORD_CHALLENGE = 'NEW_PASSWORD_REQUIRED';

    /**
     * Constant representing the force new password status.
     *
     * @var string
     */
    const FORCE_PASSWORD_STATUS = 'FORCE_CHANGE_PASSWORD';

    /**
     * AWS Cognito Client
     *
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * Cognito Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Cognito Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Cognitor Pool ID
     *
     * @var string
     */
    protected $poolId;

    /**
     * CognitoClient Constructor
     *
     * @param CognitoIdentityProviderClient $client
     * @param string                        $clientId
     * @param string                        $clientSecret
     * @param string                        $poolId
     */
    public function __construct(CognitoIdentityProviderClient $client, $clientId, $clientSecret, $poolId)
    {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
    }

    /**
     * Log a user in.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     *
     * @param  string $email
     * @param  string $password
     * @return bool
     */
    public function authenticate($email, $password)
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->cognitoSecretHash($email),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return $response;
    }

    /**
     * Registers a new user and sets their email as verified.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html
     *
     * @param  array  $credentials
     * @param  array  $attributes
     * @return bool
     */
    public function register($credentials, array $attributes = [])
    {
        $userAttributes = [];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => $key,
                'Value' => $value,
            ];
        }

        try {
            $response = $this->client->signUp([
                'ClientId' => $this->clientId,
                'Password' => $credentials['password'],
                'SecretHash' => $this->cognitoSecretHash($credentials['email']),
                'UserAttributes' => $userAttributes,
                'Username' => $credentials['email'],
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return (bool) $response['UserConfirmed'];
    }

    /**
     * Send a password reset link to a user.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
     *
     * @param  string $username
     * @return string
     */
    public function sendResetLink($username)
    {
        try {
            $this->client->forgotPassword([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return Password::INVALID_USER;
        }

        return Password::RESET_LINK_SENT;
    }

    /**
     * Reset a users password based on sent token.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html
     *
     * @param  string $code
     * @param  string $username
     * @param  string $password
     * @return string
     */
    public function resetPassword($code, $username, $password)
    {
        try {
            $this->client->confirmForgotPassword([
                'ClientId' => $this->clientId,
                'ConfirmationCode' => $code,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === 'UserNotFoundException') {
                return Password::INVALID_USER;
            }

            if ($e->getAwsErrorCode() === 'InvalidPasswordException') {
                return Password::INVALID_PASSWORD;
            }

            return Password::INVALID_TOKEN;
        }

        return Password::PASSWORD_RESET;
    }

    /**
     * Register a user and send them an email to set their password.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
     *
     * @param  string $email
     * @param  array  $attributes
     * @return bool
     */
    public function inviteUser($username, array $attributes = [])
    {
        $userAttributes = [
            [
                'Name' => 'email',
                'Value' => $username
            ],
            [
                'Name' => 'email_verified',
                'Value' => 'true'
            ]
        ];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => $key,
                'Value' => $value,
            ];
        }

        try {
            $this->client->AdminCreateUser([
                'UserPoolId' => $this->poolId,
                'TemporaryPassword' => Str::random(40),
                'DesiredDeliveryMediums' => [
                    'EMAIL'
                ],
                'Username' => $username,
                'UserAttributes' => $userAttributes,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return true;
    }

    /**
     * Set a new password for a user that has been flagged as needing a password change.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html
     *
     * @param  string $username
     * @param  string $password
     * @param  string $session
     * @return bool
     */
    public function confirmPassword($username, $password, $session)
    {
        try {
            $this->client->AdminRespondToAuthChallenge([
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
                'Session'  => $session,
                'ChallengeResponses' => [
                    'NEW_PASSWORD' => $password,
                    'USERNAME' => $username,
                    'SECRET_HASH' => $this->cognitoSecretHash($username)
                ],
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED'
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return Password::INVALID_TOKEN;
        }

        return Password::PASSWORD_RESET;
    }

    /**
     * Get user details.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html
     *
     * @param  string $username
     * @return mixed
     */
    public function getUser($username)
    {
        try {
            $user = $this->client->AdminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return $user;
    }

    /**
     * Create Cognito secret hash
     *
     * @param  string $username
     * @return string
     */
    protected function cognitoSecretHash($username)
    {
        return $this->hash($username . $this->clientId);
    }

    /**
     * Create HMAC from string
     *
     * @param  string $message
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }
}
