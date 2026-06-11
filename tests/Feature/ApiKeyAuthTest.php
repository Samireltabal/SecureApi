<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\AuditLog;
use SamirEltabal\SecureApi\Models\Credential;

beforeEach(function () {
    config()->set('auth.guards.test-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);

    $this->app['router']
        ->middleware(['auth:test-api'])
        ->get('/protected', fn () => response()->json(['ok' => true]));
});

test('valid api key authenticates and returns 200', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertOk()
        ->assertJson(['ok' => true]);
});

test('valid api key works via X-Api-Key header', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('X-Api-Key', $issued->plaintextKey)
        ->getJson('/protected')
        ->assertOk();
});

test('wrong secret returns 401', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    // Same key_id, different secret
    $tampered = "sk_{$issued->credential->id}_".str_repeat('a', 64);

    $this->withHeader('Authorization', "Bearer {$tampered}")
        ->getJson('/protected')
        ->assertUnauthorized();
});

test('completely invalid token format returns 401', function () {
    $this->withHeader('Authorization', 'Bearer not-a-real-key')
        ->getJson('/protected')
        ->assertUnauthorized();
});

test('missing token returns 401', function () {
    $this->getJson('/protected')
        ->assertUnauthorized();
});

test('revoked credential returns 401', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);
    SecureApi::revokeCredential($issued->credential->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertUnauthorized();
});

test('expired credential returns 401', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, [
        'expires_at' => now()->subMinute(),
    ]);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertUnauthorized();
});

test('credential belonging to revoked application returns 401', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);
    SecureApi::revokeApplication($app->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertUnauthorized();
});

test('authentication updates last_used_at on credential', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    expect($issued->credential->last_used_at)->toBeNull();

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();

    expect(Credential::find($issued->credential->id)->last_used_at)->not->toBeNull();
});

test('resolved application is accessible as auth user', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->app['router']
        ->middleware(['auth:test-api'])
        ->get('/me', fn () => response()->json(['id' => auth('test-api')->id()]));

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/me')
        ->assertOk()
        ->assertJson(['id' => $app->id]);
});

test('rejection writes audit log immediately', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);
    $tampered = "sk_{$issued->credential->id}_".str_repeat('b', 64);

    expect(AuditLog::count())->toBe(0);

    $this->withHeader('Authorization', "Bearer {$tampered}")
        ->getJson('/protected')
        ->assertUnauthorized();

    expect(AuditLog::count())->toBe(1);
    expect(AuditLog::first()->event)->toBe('auth.failed');
});
