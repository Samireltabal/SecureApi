<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Exceptions\MtlsNotEnabled;
use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\Credential;

function generateTestCert(): array
{
    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    $csr = openssl_csr_new(['CN' => 'test-client'], $key, ['digest_alg' => 'sha256']);
    $cert = openssl_csr_sign($csr, null, $key, 1);
    openssl_x509_export($cert, $pem);
    $fingerprint = openssl_x509_fingerprint($cert, 'sha256', false);

    return ['pem' => $pem, 'fingerprint' => $fingerprint];
}

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('auth.guards.test-mtls', [
        'driver' => 'secureapi',
        'mechanisms' => ['mtls'],
    ]);

    $this->app['router']
        ->middleware(['auth:test-mtls'])
        ->get('/mtls-protected', fn () => response()->json(['ok' => true]));

    $this->application = SecureApi::createApplication('mTLS Test App');
});

test('disabled mtls throws MtlsNotEnabled', function () {
    config()->set('secureapi.mtls.enabled', false);

    $this->withoutExceptionHandling()
        ->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->get('/mtls-protected');
})->throws(MtlsNotEnabled::class);

test('empty trusted proxies throws MtlsNotEnabled', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', []);

    $this->withoutExceptionHandling()
        ->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->get('/mtls-protected');
})->throws(MtlsNotEnabled::class);

test('request from untrusted IP returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $this->withServerVariables(['REMOTE_ADDR' => '1.2.3.4'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode('fake-cert'),
        ])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('valid certificate authenticates successfully', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    Credential::create([
        'application_id' => $this->application->id,
        'type' => 'mtls_cert',
        'name' => 'test',
        'certificate_fingerprint' => $cert['fingerprint'],
        'is_active' => true,
    ]);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode($cert['pem']),
        ])
        ->getJson('/mtls-protected')
        ->assertOk();
});

test('wrong certificate fingerprint returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    Credential::create([
        'application_id' => $this->application->id,
        'type' => 'mtls_cert',
        'certificate_fingerprint' => str_repeat('a', 64), // wrong fingerprint
        'is_active' => true,
    ]);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode($cert['pem']),
        ])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('verify header not SUCCESS returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'FAILED',
            'ssl-client-cert' => urlencode($cert['pem']),
        ])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('missing verify header returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders(['ssl-client-cert' => urlencode($cert['pem'])])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('missing cert header returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders(['ssl-client-verify' => 'SUCCESS'])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('invalid certificate PEM returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode('not-a-valid-pem'),
        ])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('revoked certificate credential returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    Credential::create([
        'application_id' => $this->application->id,
        'type' => 'mtls_cert',
        'certificate_fingerprint' => $cert['fingerprint'],
        'is_active' => false,
        'revoked_at' => now(),
    ]);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode($cert['pem']),
        ])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('expired certificate credential returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    Credential::create([
        'application_id' => $this->application->id,
        'type' => 'mtls_cert',
        'certificate_fingerprint' => $cert['fingerprint'],
        'is_active' => true,
        'expires_at' => now()->subSecond(),
    ]);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode($cert['pem']),
        ])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('inactive application returns 401', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    Credential::create([
        'application_id' => $this->application->id,
        'type' => 'mtls_cert',
        'certificate_fingerprint' => $cert['fingerprint'],
        'is_active' => true,
    ]);

    SecureApi::revokeApplication($this->application->id);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode($cert['pem']),
        ])
        ->getJson('/mtls-protected')
        ->assertStatus(401);
});

test('successful authentication updates last_used_at', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $cert = generateTestCert();

    $credential = Credential::create([
        'application_id' => $this->application->id,
        'type' => 'mtls_cert',
        'certificate_fingerprint' => $cert['fingerprint'],
        'is_active' => true,
    ]);

    expect($credential->last_used_at)->toBeNull();

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeaders([
            'ssl-client-verify' => 'SUCCESS',
            'ssl-client-cert' => urlencode($cert['pem']),
        ])
        ->getJson('/mtls-protected')
        ->assertOk();

    expect(Credential::find($credential->id)->last_used_at)->not->toBeNull();
});
