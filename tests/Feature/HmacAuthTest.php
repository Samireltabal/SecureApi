<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Signing\SignsRequests;

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('auth.guards.test-hmac', [
        'driver' => 'secureapi',
        'mechanisms' => ['hmac'],
    ]);

    $this->app['router']
        ->middleware(['auth:test-hmac'])
        ->get('/hmac-protected', fn () => response()->json(['ok' => true]));

    $this->app['router']
        ->middleware(['auth:test-hmac'])
        ->post('/hmac-protected', fn () => response()->json(['ok' => true]));

    $this->application = SecureApi::createApplication('HMAC Test App');
    $this->issued = SecureApi::createHmacCredential($this->application->id);
    $this->signer = new SignsRequests($this->issued->credential->id, $this->issued->plaintextKey);
});

/**
 * Sign a GET request with empty body and include Accept: application/json so that
 * unauthenticated responses return 401 instead of redirecting to /login.
 *
 * @return array<string, string>
 */
function hmacGetHeaders(SignsRequests $signer, string $path, ?int $timestamp = null, ?string $nonce = null): array
{
    return array_merge(
        $signer->sign('GET', $path, '', $timestamp, $nonce),
        ['Accept' => 'application/json'],
    );
}

/**
 * Build a $_SERVER array for use with call() for signed POST requests.
 * withHeaders() is ignored by call() — headers must go in the $server array.
 *
 * @param  array<string,string>  $signingHeaders
 * @return array<string,string>
 */
function hmacPostServer(array $signingHeaders): array
{
    $server = ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json'];
    foreach ($signingHeaders as $name => $value) {
        $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
    }

    return $server;
}

test('valid signed GET returns 200', function () {
    $this->withHeaders(hmacGetHeaders($this->signer, '/hmac-protected'))
        ->get('/hmac-protected')
        ->assertOk();
});

test('wrong secret returns 401', function () {
    $badSigner = new SignsRequests($this->issued->credential->id, str_repeat('a', 64));

    $this->withHeaders(hmacGetHeaders($badSigner, '/hmac-protected'))
        ->get('/hmac-protected')
        ->assertUnauthorized();
});

test('valid signed POST with body returns 200', function () {
    $body = '{"action":"read"}';
    $headers = $this->signer->sign('POST', '/hmac-protected', $body);

    $this->call('POST', '/hmac-protected', [], [], [], hmacPostServer($headers), $body)
        ->assertOk();
});

test('tampered body returns 401', function () {
    $originalBody = '{"action":"read"}';
    $tamperedBody = '{"action":"write"}';
    $headers = $this->signer->sign('POST', '/hmac-protected', $originalBody);

    $this->call('POST', '/hmac-protected', [], [], [], hmacPostServer($headers), $tamperedBody)
        ->assertUnauthorized();
});

test('tampered path returns 401', function () {
    $this->withHeaders(hmacGetHeaders($this->signer, '/other-path'))
        ->get('/hmac-protected')
        ->assertUnauthorized();
});

test('expired timestamp returns 401', function () {
    $this->withHeaders(hmacGetHeaders($this->signer, '/hmac-protected', time() - 400))
        ->get('/hmac-protected')
        ->assertUnauthorized();
});

test('future timestamp outside window returns 401', function () {
    $this->withHeaders(hmacGetHeaders($this->signer, '/hmac-protected', time() + 400))
        ->get('/hmac-protected')
        ->assertUnauthorized();
});

test('replayed nonce returns 401', function () {
    $nonce = 'fixed-test-nonce';

    $this->withHeaders(hmacGetHeaders($this->signer, '/hmac-protected', null, $nonce))
        ->get('/hmac-protected')
        ->assertOk();

    $this->withHeaders(hmacGetHeaders($this->signer, '/hmac-protected', null, $nonce))
        ->get('/hmac-protected')
        ->assertUnauthorized();
});

test('missing signature header returns 401', function () {
    $this->withHeaders(['Accept' => 'application/json'])
        ->get('/hmac-protected')
        ->assertUnauthorized();
});

test('revoked credential returns 401', function () {
    SecureApi::revokeCredential($this->issued->credential->id);

    $this->withHeaders(hmacGetHeaders($this->signer, '/hmac-protected'))
        ->get('/hmac-protected')
        ->assertUnauthorized();
});

test('valid hmac auth updates last_used_at', function () {
    expect($this->issued->credential->last_used_at)->toBeNull();

    $this->withHeaders(hmacGetHeaders($this->signer, '/hmac-protected'))
        ->get('/hmac-protected')
        ->assertOk();

    expect(Credential::find($this->issued->credential->id)->last_used_at)->not->toBeNull();
});

test('hmac failure does not fall through to api_key', function () {
    config()->set('auth.guards.multi-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['hmac', 'api_key'],
    ]);

    $this->app['router']
        ->middleware(['auth:multi-api'])
        ->get('/multi-protected', fn () => response()->json(['ok' => true]));

    $apiKeyIssued = SecureApi::createApiKeyCredential($this->application->id);

    $badSigner = new SignsRequests($this->issued->credential->id, str_repeat('b', 64));
    $headers = array_merge(
        $badSigner->sign('GET', '/multi-protected'),
        ['Accept' => 'application/json', 'Authorization' => "Bearer {$apiKeyIssued->plaintextKey}"],
    );

    $this->withHeaders($headers)->get('/multi-protected')->assertUnauthorized();
});
