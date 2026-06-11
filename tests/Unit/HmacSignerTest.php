<?php

declare(strict_types=1);

use SamirEltabal\SecureApi\Support\HmacSigner;

test('buildStringToSign uses correct format', function () {
    $signer = new HmacSigner;
    $body = '{"test":true}';
    $bodyHash = hash('sha256', $body);

    $result = $signer->buildStringToSign('POST', '/api/orders', '1700000000', 'my-nonce', $body);

    expect($result)->toBe("POST\n/api/orders\n1700000000\nmy-nonce\n{$bodyHash}");
});

test('buildStringToSign uppercases the method', function () {
    $signer = new HmacSigner;
    $result = $signer->buildStringToSign('get', '/path', '123', 'nonce', '');
    expect(str_starts_with($result, 'GET'))->toBeTrue();
});

test('buildStringToSign hashes empty body as sha256 of empty string', function () {
    $signer = new HmacSigner;
    $result = $signer->buildStringToSign('GET', '/path', '123', 'nonce', '');
    expect(str_ends_with($result, hash('sha256', '')))->toBeTrue();
});

test('sign returns hmac sha256 hex', function () {
    $signer = new HmacSigner;
    $stringToSign = "GET\n/test\n123\nnonce\n".hash('sha256', '');
    expect($signer->sign($stringToSign, 'secret'))->toBe(hash_hmac('sha256', $stringToSign, 'secret'));
});

test('verify returns true for correct signature', function () {
    $signer = new HmacSigner;
    $sts = "GET\n/test\n123\nnonce\n".hash('sha256', '');
    $sig = $signer->sign($sts, 'secret');
    expect($signer->verify($sts, 'secret', $sig))->toBeTrue();
});

test('verify returns false for wrong signature', function () {
    $signer = new HmacSigner;
    $sts = "GET\n/test\n123\nnonce\n".hash('sha256', '');
    expect($signer->verify($sts, 'secret', 'not-the-sig'))->toBeFalse();
});

test('verify is constant-time safe for length-differing inputs', function () {
    $signer = new HmacSigner;
    $sts = "GET\n/test\n123\nnonce\n".hash('sha256', '');
    expect($signer->verify($sts, 'secret', 'short'))->toBeFalse();
});
