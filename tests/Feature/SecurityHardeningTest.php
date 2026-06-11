<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Exceptions\MtlsNotEnabled;
use SamirEltabal\SecureApi\Facades\SecureApi;

// Guard used for multi-mechanism tests
function setupMixedGuard(string $guardName, array $mechanisms): void
{
    config()->set("auth.guards.{$guardName}", [
        'driver' => 'secureapi',
        'mechanisms' => $mechanisms,
    ]);
}

beforeEach(function () {
    config()->set('cache.default', 'array');
    $this->application = SecureApi::createApplication('Hardening Test App');
});

// ---------------------------------------------------------------------------
// No-fallthrough: once a mechanism supports() and authenticate() fails,
// the guard stops — it does NOT try the next mechanism.
// ---------------------------------------------------------------------------

test('hmac failure does not fall through to api key in mixed guard', function () {
    setupMixedGuard('test-mixed', ['hmac', 'api_key']);
    $this->app['router']
        ->middleware(['auth:test-mixed'])
        ->get('/mixed-protected', fn () => response()->json(['ok' => true]));

    $issued = SecureApi::createApiKeyCredential($this->application->id);
    $hmacIssued = SecureApi::createHmacCredential($this->application->id);

    // Presents a valid API key but also a malformed HMAC signature — HMAC wins
    // the supports() check (Authorization header present in HMAC format),
    // fails authenticate(), and the guard stops immediately.
    $this->withHeaders([
        'Authorization' => "Bearer {$issued->plaintextKey}", // api_key format
        'X-SecureApi-Signature' => 'invalid-hmac-sig',       // triggers HMAC supports()
        'X-SecureApi-Timestamp' => (string) time(),
        'X-SecureApi-Nonce' => 'any-nonce',
    ])
        ->getJson('/mixed-protected')
        ->assertStatus(401);
});

test('api key failure does not fall through to jwt in mixed guard', function () {
    setupMixedGuard('test-mixed2', ['api_key', 'jwt']);
    $this->app['router']
        ->middleware(['auth:test-mixed2'])
        ->get('/mixed-protected2', fn () => response()->json(['ok' => true]));

    // Presents something that looks like an API key (sk_ prefix, right length)
    // but with wrong secret — api_key supports() is true, authenticate() fails,
    // guard stops; jwt is never tried.
    $fakeKey = 'sk_'.str_repeat('a', 26).'_'.str_repeat('b', 64);

    $this->withHeader('Authorization', "Bearer {$fakeKey}")
        ->getJson('/mixed-protected2')
        ->assertStatus(401);
});

// ---------------------------------------------------------------------------
// Fail-loud: disabled mTLS bubbles as 500 even when api_key is downstream
// ---------------------------------------------------------------------------

test('disabled mtls bubbles even when api key is downstream', function () {
    config()->set('secureapi.mtls.enabled', false);
    setupMixedGuard('test-mixed3', ['mtls', 'api_key']);
    $this->app['router']
        ->middleware(['auth:test-mixed3'])
        ->get('/mixed-protected3', fn () => response()->json(['ok' => true]));

    $issued = SecureApi::createApiKeyCredential($this->application->id);

    $this->withoutExceptionHandling()
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/mixed-protected3');
})->throws(MtlsNotEnabled::class);

// ---------------------------------------------------------------------------
// Malformed input hardening — none should cause a 500
// ---------------------------------------------------------------------------

test('malformed api key formats return 401 not 500', function (string $token) {
    setupMixedGuard('test-apikey-fuzz', ['api_key']);
    $this->app['router']
        ->middleware(['auth:test-apikey-fuzz'])
        ->get('/apikey-fuzz', fn () => response()->json(['ok' => true]));

    $this->withHeader('Authorization', "Bearer {$token}")
        ->getJson('/apikey-fuzz')
        ->assertStatus(401);
})->with([
    'too short' => ['sk_short'],
    'wrong prefix' => ['xx_'.str_repeat('a', 26).'_'.str_repeat('b', 64)],
    'missing separator' => ['sk_'.str_repeat('a', 90)],
    'empty' => [''],
    'spaces only' => ['   '],
    'extra long' => [str_repeat('a', 512)],
]);

test('malformed jwt returns 401 not 500', function (string $token) {
    setupMixedGuard('test-jwt-fuzz', ['jwt']);
    $this->app['router']
        ->middleware(['auth:test-jwt-fuzz'])
        ->get('/jwt-fuzz', fn () => response()->json(['ok' => true]));

    $this->withHeader('Authorization', "Bearer {$token}")
        ->getJson('/jwt-fuzz')
        ->assertStatus(401);
})->with([
    'garbage' => ['notajwt'],
    'two dots' => ['a.b'],
    'empty parts' => ['..'],
    'binary' => ["\x00\x01\x02"],
    'alg none' => ['eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.'],
]);

test('missing authorization header returns 401', function () {
    setupMixedGuard('test-noauth', ['api_key']);
    $this->app['router']
        ->middleware(['auth:test-noauth'])
        ->get('/noauth', fn () => response()->json(['ok' => true]));

    $this->getJson('/noauth')->assertStatus(401);
});
