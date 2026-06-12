<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Exceptions\MtlsNotEnabled;
use SamirEltabal\SecureApi\Facades\SecureApi;

beforeEach(function () {
    config()->set('cache.default', 'array');
    $this->application = SecureApi::createApplication('Hardening Test App');
});

// ---------------------------------------------------------------------------
// No-fallthrough: once a mechanism supports() and authenticate() fails,
// the middleware stops — it does NOT try the next mechanism.
// ---------------------------------------------------------------------------

test('hmac failure does not fall through to api key in mixed middleware', function () {
    $this->app['router']
        ->middleware(['secureapi:hmac,api_key'])
        ->get('/mixed-protected', fn () => response()->json(['ok' => true]));

    $issued = SecureApi::createApiKeyCredential($this->application->id);
    SecureApi::createHmacCredential($this->application->id);

    // Presents a valid API key but also a malformed HMAC signature — HMAC wins
    // the supports() check (signature header present), fails authenticate(), and
    // the middleware stops immediately.
    $this->withHeaders([
        'Authorization' => "Bearer {$issued->plaintextKey}",
        'X-SecureApi-Signature' => 'invalid-hmac-sig',
        'X-SecureApi-Timestamp' => (string) time(),
        'X-SecureApi-Nonce' => 'any-nonce',
    ])
        ->getJson('/mixed-protected')
        ->assertStatus(401);
});

test('api key failure does not fall through to jwt in mixed middleware', function () {
    $this->app['router']
        ->middleware(['secureapi:api_key,jwt'])
        ->get('/mixed-protected2', fn () => response()->json(['ok' => true]));

    // Presents something that looks like an API key (sk_ prefix, right length)
    // but with wrong secret — api_key supports() is true, authenticate() fails,
    // middleware stops; jwt is never tried.
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

    $this->app['router']
        ->middleware(['secureapi:mtls,api_key'])
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
    $this->app['router']
        ->middleware(['secureapi:api_key'])
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
    $this->app['router']
        ->middleware(['secureapi:jwt'])
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
    $this->app['router']
        ->middleware(['secureapi:api_key'])
        ->get('/noauth', fn () => response()->json(['ok' => true]));

    $this->getJson('/noauth')->assertStatus(401);
});
