<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Tests;

class OauthDisabledTestCase extends TestCase
{
    public function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        config()->set('secureapi.oauth.enabled', false);
    }
}
