<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Support\JwtManager;

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('auth.guards.test-jwt', [
        'driver' => 'secureapi',
        'mechanisms' => ['jwt'],
    ]);

    $this->app['router']
        ->middleware(['auth:test-jwt'])
        ->get('/jwt-protected', fn () => response()->json(['ok' => true]));

    $this->application = SecureApi::createApplication('JWT Test App');
    $this->credential = SecureApi::createJwtCredential($this->application->id);
});

test('valid jwt bearer returns 200', function () {
    $token = SecureApi::issueToken($this->application->id);

    $this->withHeaders(['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertOk();
});

test('expired jwt returns 401', function () {
    $token = SecureApi::issueToken($this->application->id, ['ttl' => -10]);

    $this->withHeaders(['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('alg=none jwt returns 401', function () {
    $now = time();
    $b64 = fn (string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');

    $header = $b64('{"alg":"none","typ":"JWT"}');
    $payload = $b64(json_encode([
        'sub' => $this->credential->id,
        'jti' => 'algnone-attack',
        'iat' => $now,
        'nbf' => $now,
        'exp' => $now + 3600,
        'iss' => 'http://localhost',
        'aud' => ['http://localhost'],
    ]));
    $noneToken = "{$header}.{$payload}.";

    $this->withHeaders(['Authorization' => "Bearer {$noneToken}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('algorithm confusion token returns 401', function () {
    $publicKey = config('secureapi.jwt.public_key');

    $hmacConfig = Configuration::forSymmetricSigner(
        new HmacSha256,
        InMemory::plainText($publicKey),
    );

    $now = new DateTimeImmutable;
    $confusionToken = $hmacConfig->builder()
        ->relatedTo($this->credential->id)
        ->identifiedBy('confusion-jti')
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->issuedBy('http://localhost')
        ->permittedFor('http://localhost')
        ->getToken($hmacConfig->signer(), $hmacConfig->signingKey())
        ->toString();

    $this->withHeaders(['Authorization' => "Bearer {$confusionToken}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('tampered payload returns 401', function () {
    $realToken = SecureApi::issueToken($this->application->id);
    [$header, , $signature] = explode('.', $realToken);

    $b64 = fn (string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    $now = time();
    $maliciousPayload = $b64(json_encode([
        'sub' => $this->credential->id,
        'jti' => 'forged-forever',
        'iat' => $now,
        'nbf' => $now,
        'exp' => $now + 86400 * 365,
        'iss' => 'http://localhost',
        'aud' => ['http://localhost'],
    ]));

    $tamperedToken = "{$header}.{$maliciousPayload}.{$signature}";

    $this->withHeaders(['Authorization' => "Bearer {$tamperedToken}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('revoked jti returns 401', function () {
    $token = SecureApi::issueToken($this->application->id);

    $jwtManager = app(JwtManager::class);
    $parsed = $jwtManager->parse($token);
    $jti = $parsed->claims()->get('jti');

    SecureApi::revokeJwt($jti);

    $this->withHeaders(['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('revoked credential returns 401', function () {
    $token = SecureApi::issueToken($this->application->id);

    SecureApi::revokeCredential($this->credential->id);

    $this->withHeaders(['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('inactive application returns 401', function () {
    $token = SecureApi::issueToken($this->application->id);

    SecureApi::revokeApplication($this->application->id);

    $this->withHeaders(['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('missing auth header returns 401', function () {
    $this->withHeaders(['Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('non-bearer authorization returns 401', function () {
    $this->withHeaders(['Authorization' => 'Basic dXNlcjpwYXNz', 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertUnauthorized();
});

test('api key format bearer does not trigger jwt auth', function () {
    config()->set('auth.guards.multi-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['jwt', 'api_key'],
    ]);

    $this->app['router']
        ->middleware(['auth:multi-api'])
        ->get('/multi-protected', fn () => response()->json(['ok' => true]));

    $apiKeyIssued = SecureApi::createApiKeyCredential($this->application->id);

    $this->withHeaders([
        'Authorization' => "Bearer {$apiKeyIssued->plaintextKey}",
        'Accept' => 'application/json',
    ])->get('/multi-protected')->assertOk();
});

test('valid jwt auth updates last_used_at', function () {
    expect($this->credential->last_used_at)->toBeNull();

    $token = SecureApi::issueToken($this->application->id);

    $this->withHeaders(['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertOk();

    expect(Credential::find($this->credential->id)->last_used_at)->not->toBeNull();
});

test('scopes are embedded in jwt and returned in auth result', function () {
    $credential = SecureApi::createJwtCredential($this->application->id, ['scopes' => ['read', 'write']]);
    $token = SecureApi::issueToken($this->application->id, ['credential_id' => $credential->id]);

    config()->set('auth.guards.scoped-jwt', [
        'driver' => 'secureapi',
        'mechanisms' => ['jwt'],
    ]);

    $scopeResult = null;
    $this->app['router']
        ->middleware(['auth:scoped-jwt'])
        ->get('/scoped-jwt', function () use (&$scopeResult) {
            /** @var Request $request */
            $request = request();
            $cred = $request->apiCredential();
            $scopeResult = $cred?->scopes;

            return response()->json(['ok' => true]);
        });

    $this->withHeaders(['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'])
        ->get('/scoped-jwt')
        ->assertOk();

    expect($scopeResult)->toBe(['read', 'write']);
});

test('externally-signed token with trusted public key validates', function () {
    // External party has their own key pair — we hold only their public key
    $extRes = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($extRes, $extPrivKey);
    $extPubKey = openssl_pkey_get_details($extRes)['key'];

    // Reconfigure JwtManager in verify-only mode (no private key)
    config()->set('secureapi.jwt.public_key', $extPubKey);
    config()->set('secureapi.jwt.private_key', null);
    $this->app->forgetInstance(JwtManager::class);

    // External party issues the token with their private key
    $extConfig = Configuration::forAsymmetricSigner(
        new RsaSha256,
        InMemory::plainText($extPrivKey),
        InMemory::plainText($extPubKey),
    );
    $now = new DateTimeImmutable;
    $extToken = $extConfig->builder()
        ->relatedTo($this->credential->id)
        ->identifiedBy('ext-jti-1')
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->issuedBy('http://localhost')
        ->permittedFor('http://localhost')
        ->getToken($extConfig->signer(), $extConfig->signingKey())
        ->toString();

    $this->withHeaders(['Authorization' => "Bearer {$extToken}", 'Accept' => 'application/json'])
        ->get('/jwt-protected')
        ->assertOk();
});

test('jwt failure does not fall through when bearer present', function () {
    config()->set('auth.guards.jwt-then-apikey', [
        'driver' => 'secureapi',
        'mechanisms' => ['jwt', 'api_key'],
    ]);

    $this->app['router']
        ->middleware(['auth:jwt-then-apikey'])
        ->get('/fallthrough-protected', fn () => response()->json(['ok' => true]));

    $apiKeyIssued = SecureApi::createApiKeyCredential($this->application->id);

    $b64 = fn (string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    $now = time();
    $header = $b64('{"alg":"RS256","typ":"JWT"}');
    $payload = $b64(json_encode(['sub' => 'nonexistent', 'exp' => $now + 3600, 'iat' => $now, 'nbf' => $now]));
    $badJwt = "{$header}.{$payload}.invalidsignature";

    $this->withHeaders([
        'Authorization' => "Bearer {$badJwt}",
        'X-Api-Key' => $apiKeyIssued->plaintextKey,
        'Accept' => 'application/json',
    ])->get('/fallthrough-protected')->assertUnauthorized();
});
