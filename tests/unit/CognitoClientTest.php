<?php

use Mockery as Mock;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use PodPoint\LaravelCognitoAuth\CognitoClient;

class CognitoClientTest extends TestCase
{
    /**
     * Executed before each test.
     */
    protected function setUp()
    {
        $this->aws = Mock::mock(CognitoIdentityProviderClient::class);
        $this->client = new CognitoClient($this->aws, 'clientId', 'clientSecret', 'poolId');
    }

    /**
     * Test a valid cognito secret hash can be generated
     */
    public function testSecretHashCanBeGenerated()
    {
        $this->aws->shouldReceive('forgotPassword')->with(Mockery::on(function ($value) {
            return $value['SecretHash'] == 'iBoYbAtSXHBdi/y0nB5iLseaWMsRY/ml+fYIqVb2yTs=';
        }));

        $this->client->sendResetLink('username@host.com');
    }

    /**
     * Tests a users email is marked as verified when they are registered
     */
    public function testRegisteredUsersEmailsAreVerified()
    {
        $this->aws->shouldReceive('signUp');
        $this->aws->shouldReceive('AdminUpdateUserAttributes')->with(Mockery::on(function ($value) {
            return $value['UserAttributes'][0]['Name'] == 'email_verified';
        }));

        $this->client->register('username@host.com', 'password');
    }
}
