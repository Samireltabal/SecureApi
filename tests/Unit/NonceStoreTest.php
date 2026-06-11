<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Support\NonceStore;

beforeEach(function () {
    config()->set('cache.default', 'array');
});

test('consume returns true on first use', function () {
    $store = new NonceStore;
    expect($store->consume('key1', 'nonce1', 300))->toBeTrue();
});

test('consume returns false on replay', function () {
    $store = new NonceStore;
    $store->consume('key1', 'nonce1', 300);
    expect($store->consume('key1', 'nonce1', 300))->toBeFalse();
});

test('different nonces are independent', function () {
    $store = new NonceStore;
    expect($store->consume('key1', 'nonce-a', 300))->toBeTrue();
    expect($store->consume('key1', 'nonce-b', 300))->toBeTrue();
});

test('same nonce for different key ids are independent', function () {
    $store = new NonceStore;
    expect($store->consume('key1', 'nonce1', 300))->toBeTrue();
    expect($store->consume('key2', 'nonce1', 300))->toBeTrue();
});
