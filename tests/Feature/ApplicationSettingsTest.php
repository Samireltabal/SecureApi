<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use SamirEltabal\SecureApi\Facades\SecureApi;
use SamirEltabal\SecureApi\Models\ApplicationSetting;

uses(RefreshDatabase::class);

test('can set and retrieve a string setting', function () {
    $application = SecureApi::createApplication('Test App');

    $application->setSetting('webhook_url', 'https://example.com/hook');

    expect($application->getSetting('webhook_url'))->toBe('https://example.com/hook');
});

test('can set and retrieve an integer setting', function () {
    $application = SecureApi::createApplication('Test App');

    $application->setSetting('retry_attempts', 3);

    expect($application->getSetting('retry_attempts'))->toBe(3);
});

test('can set and retrieve an array setting', function () {
    $application = SecureApi::createApplication('Test App');

    $application->setSetting('allowed_events', ['order.created', 'order.shipped']);

    expect($application->getSetting('allowed_events'))->toBe(['order.created', 'order.shipped']);
});

test('returns null when setting is not found', function () {
    $application = SecureApi::createApplication('Test App');

    expect($application->getSetting('missing_key'))->toBeNull();
});

test('returns default when setting is not found', function () {
    $application = SecureApi::createApplication('Test App');

    expect($application->getSetting('missing_key', 'fallback'))->toBe('fallback');
});

test('can forget a setting', function () {
    $application = SecureApi::createApplication('Test App');
    $application->setSetting('webhook_url', 'https://example.com/hook');

    $application->forgetSetting('webhook_url');

    expect($application->getSetting('webhook_url'))->toBeNull();
});

test('forgetting a nonexistent setting does not throw', function () {
    $application = SecureApi::createApplication('Test App');

    expect(fn () => $application->forgetSetting('no_such_key'))->not->toThrow(Throwable::class);
});

test('can update an existing setting', function () {
    $application = SecureApi::createApplication('Test App');
    $application->setSetting('webhook_url', 'https://old.example.com/hook');
    $application->setSetting('webhook_url', 'https://new.example.com/hook');

    expect($application->getSetting('webhook_url'))->toBe('https://new.example.com/hook');
});

test('settings are scoped to their application', function () {
    $appA = SecureApi::createApplication('App A');
    $appB = SecureApi::createApplication('App B');

    $appA->setSetting('token', 'app-a-token');

    expect($appB->getSetting('token'))->toBeNull();
});

test('settings are deleted when application is deleted', function () {
    $application = SecureApi::createApplication('Test App');
    $application->setSetting('key', 'value');

    $application->delete();

    expect(ApplicationSetting::count())->toBe(0);
});

test('can create application with inline settings', function () {
    $application = SecureApi::createApplication('Test App', [
        'settings' => [
            'webhook_url' => 'https://example.com/hook',
            'retry_attempts' => 3,
        ],
    ]);

    expect($application->getSetting('webhook_url'))->toBe('https://example.com/hook')
        ->and($application->getSetting('retry_attempts'))->toBe(3);
});
