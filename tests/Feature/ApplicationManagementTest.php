<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\Application;

uses(RefreshDatabase::class);

test('can create an application with minimal options', function () {
    $application = SecureApi::createApplication('Payment Gateway');

    expect($application)->toBeInstanceOf(Application::class)
        ->and($application->name)->toBe('Payment Gateway')
        ->and($application->is_active)->toBeTrue()
        ->and($application->revoked_at)->toBeNull()
        ->and($application->id)->not->toBeEmpty();
});

test('application id is a ulid', function () {
    $application = SecureApi::createApplication('Test App');

    expect(strlen($application->id))->toBe(26);
});

test('can create application with all options', function () {
    $application = SecureApi::createApplication('Billing Service', [
        'description' => 'Internal billing integration',
        'allowed_ips' => ['10.0.0.1', '192.168.1.0/24'],
        'rate_limit_per_minute' => 120,
    ]);

    expect($application->description)->toBe('Internal billing integration')
        ->and($application->allowed_ips)->toBe(['10.0.0.1', '192.168.1.0/24'])
        ->and($application->rate_limit_per_minute)->toBe(120);
});

test('can find application by id', function () {
    $created = SecureApi::createApplication('Test App');

    $found = SecureApi::findApplication($created->id);

    expect($found)->not->toBeNull()
        ->and($found->id)->toBe($created->id)
        ->and($found->name)->toBe('Test App');
});

test('find application returns null for unknown id', function () {
    expect(SecureApi::findApplication('01JZZZZZZZZZZZZZZZZZZZZZZZ'))->toBeNull();
});

test('can find application by name', function () {
    SecureApi::createApplication('Shipping Service');

    $found = SecureApi::findApplicationByName('Shipping Service');

    expect($found)->not->toBeNull()
        ->and($found->name)->toBe('Shipping Service');
});

test('find by name returns null when not found', function () {
    expect(SecureApi::findApplicationByName('nonexistent'))->toBeNull();
});

test('can revoke an application', function () {
    $application = SecureApi::createApplication('Test App');

    SecureApi::revokeApplication($application->id);

    $refreshed = SecureApi::findApplication($application->id);

    expect($refreshed->is_active)->toBeFalse()
        ->and($refreshed->revoked_at)->not->toBeNull();
});

test('application is stored in database', function () {
    SecureApi::createApplication('Stored App');

    expect(DB::table(
        config('secureapi.table_prefix', 'secure_api_').'applications'
    )->count())->toBe(1);
});
