<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Facades\SecureApi;

beforeEach(function () {
    config()->set('auth.guards.test-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);
});

test('credential with required scope passes', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.scopes:read'])
        ->get('/scoped', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, ['scopes' => ['read', 'write']]);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/scoped')
        ->assertOk();
});

test('credential missing required scope returns 403', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.scopes:write'])
        ->get('/scoped', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, ['scopes' => ['read']]);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/scoped')
        ->assertForbidden();
});

test('all required scopes must be present (AND logic)', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.scopes:read:write'])
        ->get('/scoped', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, ['scopes' => ['read']]);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/scoped')
        ->assertForbidden();
});

test('credential with null scopes passes any scope check', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.scopes:read:write:admin'])
        ->get('/scoped', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id); // no scopes = unrestricted

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/scoped')
        ->assertOk();
});

test('secureapi.scope alias works for single scope', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.scope:admin'])
        ->get('/admin-only', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, ['scopes' => ['read']]);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/admin-only')
        ->assertForbidden();
});

test('unauthenticated request is 401 not 403', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.scopes:read'])
        ->get('/scoped', fn () => response()->json(['ok' => true]));

    $this->getJson('/scoped')
        ->assertUnauthorized();
});
