<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Support\Facades\Auth;

test('secureapi guard driver resolves without exception', function () {
    config()->set('auth.guards.partner-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);

    expect(fn () => Auth::guard('partner-api'))->not->toThrow(Throwable::class);
});

test('secureapi guard returns unauthenticated by default', function () {
    config()->set('auth.guards.partner-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);

    expect(Auth::guard('partner-api')->check())->toBeFalse()
        ->and(Auth::guard('partner-api')->user())->toBeNull();
});

test('secureapi guard is a guard instance', function () {
    config()->set('auth.guards.partner-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);

    expect(Auth::guard('partner-api'))->toBeInstanceOf(Guard::class);
});

test('multiple guards with different names can coexist', function () {
    config()->set('auth.guards.partner-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['api_key'],
    ]);
    config()->set('auth.guards.internal-api', [
        'driver' => 'secureapi',
        'mechanisms' => ['hmac'],
    ]);

    expect(Auth::guard('partner-api'))->toBeInstanceOf(Guard::class)
        ->and(Auth::guard('internal-api'))->toBeInstanceOf(Guard::class);
});
