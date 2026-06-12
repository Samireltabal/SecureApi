<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\AuditLog;
use SamirEltabal\SecureApi\Models\Credential;

beforeEach(function () {
    config()->set('cache.default', 'array');

    $this->app['router']
        ->middleware(['secureapi:jwt'])
        ->get('/bearer-protected', fn () => response()->json(['ok' => true]));

    $this->application = SecureApi::createApplication('OAuth Test App');
    $this->issued = SecureApi::createOauthClientCredential($this->application->id);
    $this->clientId = $this->issued->credential->id;
    $this->clientSecret = $this->issued->plaintextKey;
});

test('token issued with valid http basic credentials', function () {
    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
        'Content-Type' => 'application/x-www-form-urlencoded',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertOk()
        ->assertJsonStructure(['access_token', 'token_type', 'expires_in', 'scope'])
        ->assertJsonPath('token_type', 'Bearer');

    expect($response->json('access_token'))->toBeString()->not->toBeEmpty();
    expect(substr_count($response->json('access_token'), '.'))->toBe(2);
});

test('token issued with valid form field credentials', function () {
    $response = $this->post('/secureapi/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->clientId,
        'client_secret' => $this->clientSecret,
    ]);

    $response->assertOk()
        ->assertJsonPath('token_type', 'Bearer');
});

test('issued token can authenticate on a jwt-guarded route', function () {
    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $accessToken = $response->json('access_token');

    $this->withHeaders([
        'Authorization' => "Bearer {$accessToken}",
        'Accept' => 'application/json',
    ])->get('/bearer-protected')->assertOk();
});

test('invalid client id returns 401 with www-authenticate header', function () {
    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("nonexistent-id:{$this->clientSecret}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');

    expect($response->headers->get('WWW-Authenticate'))->toContain('Basic');
});

test('wrong client secret returns 401', function () {
    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:wrongsecret"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

test('revoked oauth credential returns 401', function () {
    SecureApi::revokeCredential($this->clientId);

    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

test('expired oauth credential returns 401', function () {
    $this->issued->credential->update(['expires_at' => now()->subSecond()]);

    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

test('inactive application returns 401', function () {
    SecureApi::revokeApplication($this->application->id);

    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

test('unsupported grant type returns 400', function () {
    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'authorization_code']);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'unsupported_grant_type');
});

test('missing grant type returns 400', function () {
    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', []);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

test('scope not in allowed scopes returns 400', function () {
    $scopedIssued = SecureApi::createOauthClientCredential(
        $this->application->id,
        ['scopes' => ['read']],
    );

    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$scopedIssued->credential->id}:{$scopedIssued->plaintextKey}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', [
        'grant_type' => 'client_credentials',
        'scope' => 'read write',
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');
});

test('scope subset succeeds and is reflected in response', function () {
    $scopedIssued = SecureApi::createOauthClientCredential(
        $this->application->id,
        ['scopes' => ['read', 'write', 'admin']],
    );

    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$scopedIssued->credential->id}:{$scopedIssued->plaintextKey}"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', [
        'grant_type' => 'client_credentials',
        'scope' => 'read write',
    ]);

    $response->assertOk();
    expect($response->json('scope'))->toBe('read write');
});

test('success response has no-store cache control and pragma headers', function () {
    $response = $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertOk();
    expect($response->headers->get('Cache-Control'))->toContain('no-store');
    expect($response->headers->get('Pragma'))->toBe('no-cache');
});

test('successful token request updates last_used_at on credential', function () {
    expect(Credential::find($this->clientId)->last_used_at)->toBeNull();

    $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials'])->assertOk();

    expect(Credential::find($this->clientId)->last_used_at)->not->toBeNull();
});

test('failed token request is audit logged when client is identifiable', function () {
    $this->withHeaders([
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:wrongsecret"),
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    expect(
        AuditLog::where('credential_id', $this->clientId)
            ->where('event', 'auth.failed')
            ->exists()
    )->toBeTrue();
});

test('missing client credentials returns 400 invalid_request', function () {
    $response = $this->withHeaders([
        'Accept' => 'application/json',
    ])->post('/secureapi/oauth/token', ['grant_type' => 'client_credentials']);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

test('rate limiter returns 429 after per-minute limit is exceeded', function () {
    config()->set('secureapi.oauth.rate_limit_per_minute', 2);

    $headers = [
        'Authorization' => 'Basic '.base64_encode("{$this->clientId}:{$this->clientSecret}"),
        'Accept' => 'application/json',
    ];
    $body = ['grant_type' => 'client_credentials'];

    $this->withHeaders($headers)->post('/secureapi/oauth/token', $body)->assertOk();
    $this->withHeaders($headers)->post('/secureapi/oauth/token', $body)->assertOk();
    $this->withHeaders($headers)->post('/secureapi/oauth/token', $body)->assertStatus(429);
});
