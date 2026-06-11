<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Tests\Disabled;

use SamirEltabal\SecureApi\Tests\OauthDisabledTestCase;

final class OauthTokenDisabledTest extends OauthDisabledTestCase
{
    public function test_token_endpoint_is_not_registered_when_oauth_is_disabled(): void
    {
        $this->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials'])
            ->assertStatus(404);
    }
}
