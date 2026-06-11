<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Signing;

use SamirEltabal\SecureApi\Support\HmacSigner;

final class SignsRequests
{
    private readonly HmacSigner $signer;

    public function __construct(
        private readonly string $keyId,
        private readonly string $secret,
    ) {
        $this->signer = new HmacSigner;
    }

    /**
     * Build HMAC signature headers for an outgoing request.
     *
     * @return array<string, string>
     */
    public function sign(
        string $method,
        string $path,
        string $body = '',
        ?int $timestamp = null,
        ?string $nonce = null,
    ): array {
        $timestamp ??= time();
        $nonce ??= bin2hex(random_bytes(16));

        $stringToSign = $this->signer->buildStringToSign(
            $method,
            $path,
            (string) $timestamp,
            $nonce,
            $body,
        );

        return [
            'X-SecureApi-Key-Id' => $this->keyId,
            'X-SecureApi-Timestamp' => (string) $timestamp,
            'X-SecureApi-Nonce' => $nonce,
            'X-SecureApi-Signature' => $this->signer->sign($stringToSign, $this->secret),
        ];
    }

    /**
     * Returns a Guzzle handler middleware that signs outgoing requests automatically.
     */
    public function guzzleMiddleware(): \Closure
    {
        return function (callable $handler): \Closure {
            return function ($request, array $options) use ($handler) {
                $body = (string) $request->getBody();
                $path = $request->getUri()->getPath();
                $headers = $this->sign($request->getMethod(), $path, $body);

                foreach ($headers as $name => $value) {
                    $request = $request->withHeader($name, $value);
                }

                return $handler($request, $options);
            };
        };
    }
}
