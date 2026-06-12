<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\DTOs\IssuedCredential;
use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\Credential;

test('createApiKeyCredential returns IssuedCredential DTO', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    expect($issued)->toBeInstanceOf(IssuedCredential::class);
    expect($issued->credential)->toBeInstanceOf(Credential::class);
    expect($issued->plaintextKey)->toStartWith('sk_');
});

test('plaintext key follows sk_<ulid>_<64hex> format', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    expect($issued->plaintextKey)->toHaveLength(94); // sk_(3) + ulid(26) + _(1) + hex(64)
    expect(preg_match('/^sk_[0-9A-Z]{26}_[0-9a-f]{64}$/', $issued->plaintextKey))->toBe(1);
});

test('secret hash is sha256 of the raw secret', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $rawSecret = substr($issued->plaintextKey, 30); // after sk_ + ulid(26) + _
    $expectedHash = hash('sha256', $rawSecret);

    expect($issued->credential->secret_hash)->toBe($expectedHash);
});

test('each createApiKeyCredential call produces a unique key', function () {
    $app = SecureApi::createApplication('Test App');
    $a = SecureApi::createApiKeyCredential($app->id);
    $b = SecureApi::createApiKeyCredential($app->id);

    expect($a->plaintextKey)->not->toBe($b->plaintextKey);
    expect($a->credential->id)->not->toBe($b->credential->id);
});

test('credential is created with api_key type', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    expect($issued->credential->type)->toBe('api_key');
    expect($issued->credential->application_id)->toBe($app->id);
    expect($issued->credential->is_active)->toBeTrue();
});

test('credential can be created with name', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, ['name' => 'CI Bot Key']);

    expect($issued->credential->name)->toBe('CI Bot Key');
});

test('credential can be created with scopes', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, ['scopes' => ['read', 'write']]);

    expect($issued->credential->scopes)->toBe(['read', 'write']);
});

test('credential can be created with expiry', function () {
    $app = SecureApi::createApplication('Test App');
    $expires = now()->addYear();
    $issued = SecureApi::createApiKeyCredential($app->id, ['expires_at' => $expires]);

    expect($issued->credential->expires_at->toDateString())->toBe($expires->toDateString());
});

test('revokeCredential marks credential revoked', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $result = SecureApi::revokeCredential($issued->credential->id);

    expect($result)->toBeTrue();

    $fresh = Credential::find($issued->credential->id);
    expect($fresh->is_active)->toBeFalse();
    expect($fresh->revoked_at)->not->toBeNull();
});

test('revokeCredential returns false for unknown id', function () {
    $result = SecureApi::revokeCredential('01JXXXXXXXXXXXXXXXXXXXXXXX');

    expect($result)->toBeFalse();
});

test('rotateApiKeyCredential replaces secret hash and returns new key', function () {
    $app = SecureApi::createApplication('Test App');
    $original = SecureApi::createApiKeyCredential($app->id);

    $rotated = SecureApi::rotateApiKeyCredential($original->credential->id);

    expect($rotated)->toBeInstanceOf(IssuedCredential::class);
    expect($rotated->credential->id)->toBe($original->credential->id);
    expect($rotated->plaintextKey)->not->toBe($original->plaintextKey);
    expect($rotated->credential->secret_hash)->not->toBe($original->credential->secret_hash);
});

test('original key no longer works after rotation', function () {
    $this->app['router']
        ->middleware(['secureapi:api_key'])
        ->get('/protected', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $original = SecureApi::createApiKeyCredential($app->id);
    $rotated = SecureApi::rotateApiKeyCredential($original->credential->id);

    $this->withHeader('Authorization', "Bearer {$original->plaintextKey}")
        ->getJson('/protected')
        ->assertUnauthorized();

    $this->withHeader('Authorization', "Bearer {$rotated->plaintextKey}")
        ->getJson('/protected')
        ->assertOk();
});
