<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\Credential;

beforeEach(function () {
    $this->application = SecureApi::createApplication('mTLS Cmd App');
    $this->certPath = tempnam(sys_get_temp_dir(), 'mtls_test_cert_').'.pem';

    // Generate a real self-signed certificate and write it to the temp file
    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    $csr = openssl_csr_new(['CN' => 'test-cmd-client'], $key, ['digest_alg' => 'sha256']);
    $cert = openssl_csr_sign($csr, null, $key, 1);
    openssl_x509_export($cert, $pem);
    file_put_contents($this->certPath, $pem);

    $this->certFingerprint = openssl_x509_fingerprint($cert, 'sha256', false);
});

afterEach(function () {
    if (file_exists($this->certPath)) {
        unlink($this->certPath);
    }
});

test('command is blocked when mtls is disabled', function () {
    config()->set('secureapi.mtls.enabled', false);

    $this->artisan('secureapi:mtls:register', [
        'app' => $this->application->id,
        'cert' => $this->certPath,
    ])->assertFailed();
});

test('command creates mtls_cert credential with correct fingerprint', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $this->artisan('secureapi:mtls:register', [
        'app' => $this->application->id,
        'cert' => $this->certPath,
    ])->assertSuccessful();

    $credential = Credential::where('application_id', $this->application->id)
        ->where('type', 'mtls_cert')
        ->first();

    expect($credential)->not->toBeNull();
    expect($credential->certificate_fingerprint)->toBe($this->certFingerprint);
    expect($credential->is_active)->toBeTrue();
});

test('command fails when application does not exist', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $this->artisan('secureapi:mtls:register', [
        'app' => 'nonexistent-id',
        'cert' => $this->certPath,
    ])->assertFailed();
});

test('command fails when cert file does not exist', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    $this->artisan('secureapi:mtls:register', [
        'app' => $this->application->id,
        'cert' => '/tmp/does_not_exist_12345.pem',
    ])->assertFailed();
});

test('command fails when cert file contains invalid PEM', function () {
    config()->set('secureapi.mtls.enabled', true);
    config()->set('secureapi.mtls.trusted_proxies', ['10.0.0.0/8']);

    file_put_contents($this->certPath, 'not-a-valid-cert');

    $this->artisan('secureapi:mtls:register', [
        'app' => $this->application->id,
        'cert' => $this->certPath,
    ])->assertFailed();
});
