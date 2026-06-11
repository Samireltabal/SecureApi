<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Facades\SecureApi;

beforeEach(function () {
    config()->set('auth.guards.test-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);

    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.allow_ips'])
        ->get('/protected', fn () => response()->json(['ok' => true]));
});

test('request from allowed ip passes', function () {
    $app = SecureApi::createApplication('Test App', [
        'allowed_ips' => ['127.0.0.1'],
    ]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();
});

test('request from disallowed ip returns 403', function () {
    $app = SecureApi::createApplication('Test App', [
        'allowed_ips' => ['10.0.0.1'],
    ]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.100'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertForbidden();
});

test('application with null allowed_ips allows any ip', function () {
    $app = SecureApi::createApplication('Test App'); // no allowed_ips
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.1'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();
});

test('ip in cidr range passes', function () {
    $app = SecureApi::createApplication('Test App', [
        'allowed_ips' => ['10.0.0.0/8'],
    ]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '10.20.30.40'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();
});

test('ip outside cidr range returns 403', function () {
    $app = SecureApi::createApplication('Test App', [
        'allowed_ips' => ['10.0.0.0/8'],
    ]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.1'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertForbidden();
});

test('multiple ips in allowlist any match passes', function () {
    $app = SecureApi::createApplication('Test App', [
        'allowed_ips' => ['10.0.0.1', '172.16.0.5', '192.168.1.0/24'],
    ]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.50'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();
});
