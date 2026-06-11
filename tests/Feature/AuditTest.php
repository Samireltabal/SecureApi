<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\AuditLog;

beforeEach(function () {
    config()->set('auth.guards.test-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);

    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.audit'])
        ->get('/audited', fn () => response()->json(['ok' => true]));
});

test('successful request writes audit log', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/audited')
        ->assertOk();

    expect(AuditLog::count())->toBe(1);

    $log = AuditLog::first();
    expect($log->event)->toBe('auth.success');
    expect($log->application_id)->toBe($app->id);
    expect($log->credential_id)->toBe($issued->credential->id);
});

test('audit log records request method and path', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/audited')
        ->assertOk();

    $log = AuditLog::first();
    expect($log->request_method)->toBe('GET');
    expect($log->request_path)->toBe('/audited');
});

test('audit log records client ip', function () {
    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/audited')
        ->assertOk();

    expect(AuditLog::first()->ip_address)->toBe('10.0.0.1');
});

test('failed auth writes audit log even without audit middleware', function () {
    // Route WITHOUT secureapi.audit middleware
    $this->app['router']
        ->middleware(['auth:test-api'])
        ->get('/unaudited-auth', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);
    $tampered = "sk_{$issued->credential->id}_".str_repeat('c', 64);

    $this->withHeader('Authorization', "Bearer {$tampered}")
        ->getJson('/unaudited-auth')
        ->assertUnauthorized();

    expect(AuditLog::count())->toBe(1);
    expect(AuditLog::first()->event)->toBe('auth.failed');
});

test('failed auth log has correct application and credential ids', function () {
    $this->app['router']
        ->middleware(['auth:test-api'])
        ->get('/unaudited-auth', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);
    $tampered = "sk_{$issued->credential->id}_".str_repeat('d', 64);

    $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.1'])
        ->withHeader('Authorization', "Bearer {$tampered}")
        ->getJson('/unaudited-auth')
        ->assertUnauthorized();

    $log = AuditLog::first();
    expect($log->application_id)->toBe($app->id);
    expect($log->credential_id)->toBe($issued->credential->id);
    expect($log->ip_address)->toBe('192.0.2.1');
    expect($log->event)->toBe('auth.failed');
});

test('unknown key id does not write audit log', function () {
    $this->app['router']
        ->middleware(['auth:test-api'])
        ->get('/unaudited-auth', fn () => response()->json(['ok' => true]));

    // Key ID that doesn't exist in DB — no credential to link the audit to
    $unknownKey = 'sk_'.str_repeat('A', 26).'_'.str_repeat('e', 64);

    $this->withHeader('Authorization', "Bearer {$unknownKey}")
        ->getJson('/unaudited-auth')
        ->assertUnauthorized();

    expect(AuditLog::count())->toBe(0);
});

test('scope rejection writes audit log with forbidden event', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.audit', 'secureapi.scopes:write'])
        ->get('/scoped-audited', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id, ['scopes' => ['read']]);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/scoped-audited')
        ->assertForbidden();

    expect(AuditLog::count())->toBe(1);
    $log = AuditLog::first();
    expect($log->event)->toBe('auth.forbidden');
    expect($log->credential_id)->toBe($issued->credential->id);
});

test('ip rejection writes audit log with forbidden event', function () {
    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.audit', 'secureapi.allow_ips'])
        ->get('/ip-audited', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App', ['allowed_ips' => ['10.0.0.1']]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.100'])
        ->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/ip-audited')
        ->assertForbidden();

    expect(AuditLog::count())->toBe(1);
    $log = AuditLog::first();
    expect($log->event)->toBe('auth.forbidden');
    expect($log->credential_id)->toBe($issued->credential->id);
});

test('rate limit rejection writes audit log with rate_limited event', function () {
    config()->set('cache.default', 'array');

    $this->app['router']
        ->middleware(['auth:test-api', 'secureapi.audit', 'secureapi.throttle'])
        ->get('/throttled-audited', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App', ['rate_limit_per_minute' => 1]);
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/throttled-audited')
        ->assertOk();

    AuditLog::query()->delete();

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/throttled-audited')
        ->assertStatus(429);

    expect(AuditLog::count())->toBe(1);
    $log = AuditLog::first();
    expect($log->event)->toBe('auth.rate_limited');
    expect($log->credential_id)->toBe($issued->credential->id);
});

test('route without audit middleware does not write success audit', function () {
    $this->app['router']
        ->middleware(['auth:test-api'])
        ->get('/no-audit', fn () => response()->json(['ok' => true]));

    $app = SecureApi::createApplication('Test App');
    $issued = SecureApi::createApiKeyCredential($app->id);

    $this->withHeader('Authorization', "Bearer {$issued->plaintextKey}")
        ->getJson('/no-audit')
        ->assertOk();

    expect(AuditLog::count())->toBe(0);
});
