<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Support;

final class HmacSigner
{
    public function buildStringToSign(
        string $method,
        string $path,
        string $timestamp,
        string $nonce,
        string $body,
    ): string {
        return implode("\n", [
            strtoupper($method),
            $path,
            $timestamp,
            $nonce,
            hash('sha256', $body),
        ]);
    }

    public function sign(string $stringToSign, string $secret): string
    {
        return hash_hmac('sha256', $stringToSign, $secret);
    }

    public function verify(string $stringToSign, string $secret, string $signature): bool
    {
        return hash_equals($this->sign($stringToSign, $secret), $signature);
    }
}
