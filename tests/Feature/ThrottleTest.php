<?php

declare(strict_types=1);

use Illuminate\Support\Facades\RateLimiter;
use SamirEltabal\SecureApi\Facades\SecureApi;

beforeEach(function () {
    RateLimiter::clear('');
    config()->set('cache.default', 'array');

    $this->app['router']
        ->middleware(['secureapi:api_key', 'secureapi.throttle'])
        ->get('/protected', fn () => response()->json(['ok' => true]));
});

test('request under rate limit succeeds', function () {
    $app = SecureApi::createApplication('Test App', ['rate_limit_per_minute' => 5]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();
});

test('request over application rate limit returns 429', function () {
    $app = SecureApi::createApplication('Test App', ['rate_limit_per_minute' => 2]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $key = "Bearer {$issued->plaintextKey}";

    $this->withHeader('Authorization', $key)->getJson('/protected')->assertOk();
    $this->withHeader('Authorization', $key)->getJson('/protected')->assertOk();
    $this->withHeader('Authorization', $key)->getJson('/protected')->assertStatus(429);
});

test('no rate limit when application rate_limit_per_minute is null', function () {
    $app = SecureApi::createApplication('Test App'); // null rate limit
    $issued = SecureApi::createApiKeyCredential($app->id);

    config()->set('secureapi.rate_limit.default_per_minute', null);

    for ($i = 0; $i < 10; $i++) {
        $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
            ->getJson('/protected')
            ->assertOk();
    }
});

test('global default rate limit applies when application limit is null', function () {
    config()->set('secureapi.rate_limit.default_per_minute', 3);

    $app = SecureApi::createApplication('Test App'); // no specific limit
    $issued = SecureApi::createApiKeyCredential($app->id);

    $key = "Bearer {$issued->plaintextKey}";

    $this->withHeader('Authorization', $key)->getJson('/protected')->assertOk();
    $this->withHeader('Authorization', $key)->getJson('/protected')->assertOk();
    $this->withHeader('Authorization', $key)->getJson('/protected')->assertOk();
    $this->withHeader('Authorization', $key)->getJson('/protected')->assertStatus(429);
});

test('rate limits are per credential not per application', function () {
    $app = SecureApi::createApplication('Test App', ['rate_limit_per_minute' => 1]);
    $issuedA = SecureApi::createApiKeyCredential($app->id);
    $issuedB = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('Authorization', "Bearer {$issuedA->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();

    // A is now at limit, B should still work
    $this->withHeader('Authorization', "Bearer {$issuedB->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();
});
