<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Contracts\Authenticator;
use SamirEltabal\SecureApi\DTOs\AuthResult;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;
use SamirEltabal\SecureApi\Exceptions\MechanismNotConfigured;
use SamirEltabal\SecureApi\Models\AuditLog;
use SamirEltabal\SecureApi\Models\Credential;

final class SecureApiGuard implements Guard
{
    /** @param array<string, mixed> $config */
    public function __construct(
        private readonly string $name,
        private readonly array $config,
        private readonly Container $container,
    ) {}

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function guest(): bool
    {
        return ! $this->check();
    }

    public function user(): ?Authenticatable
    {
        $request = $this->currentRequest();

        if ($request->attributes->has('secureapi.auth_attempted')) {
            $result = $request->attributes->get('secureapi.auth_result');

            return $result instanceof AuthResult ? $result->application : null;
        }

        $request->attributes->set('secureapi.auth_attempted', true);

        foreach ($this->mechanisms() as $mechanism) {
            $authenticator = $this->resolveAuthenticator($mechanism);

            if (! $authenticator->supports($request)) {
                continue;
            }

            try {
                $authResult = $authenticator->authenticate($request);
                $request->attributes->set('secureapi.auth_result', $authResult);
                $request->attributes->set('secureapi.credential', $authResult->credential);

                return $authResult->application;
            } catch (AuthenticationFailedException $e) {
                $this->writeRejectionAudit($request, $e);

                return null;
            }
        }

        return null;
    }

    public function id(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    /** @param array<string, mixed> $credentials */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    public function hasUser(): bool
    {
        return $this->currentRequest()->attributes->has('secureapi.auth_result');
    }

    public function setUser(Authenticatable $user): static
    {
        return $this;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRequest(): Request
    {
        return $this->currentRequest();
    }

    /** @return string[] */
    public function mechanisms(): array
    {
        return $this->config['mechanisms'] ?? [];
    }

    private function currentRequest(): Request
    {
        return $this->container->make('request');
    }

    private function extractRawToken(Request $request): ?string
    {
        $auth = $request->header('Authorization');

        if (is_string($auth) && str_starts_with($auth, 'Bearer ')) {
            return substr($auth, 7);
        }

        $apiKey = $request->header('X-Api-Key');

        return is_string($apiKey) ? $apiKey : null;
    }

    private function resolveAuthenticator(string $mechanism): Authenticator
    {
        $key = "secureapi.auth.{$mechanism}";

        if (! $this->container->bound($key)) {
            throw MechanismNotConfigured::forMechanism($mechanism, $this->name);
        }

        return $this->container->make($key);
    }

    private function writeRejectionAudit(Request $request, AuthenticationFailedException $e): void
    {
        $token = $this->extractRawToken($request);

        if ($token === null || strlen($token) !== 94 || ! str_starts_with($token, 'sk_')) {
            return;
        }

        $keyId = substr($token, 3, 26);
        $credential = Credential::find($keyId);

        if ($credential === null) {
            return;
        }

        AuditLog::create([
            'application_id' => $credential->application_id,
            'credential_id' => $credential->id,
            'event' => 'auth.failed',
            'ip_address' => $request->ip(),
            'request_method' => $request->method(),
            'request_path' => $request->getPathInfo(),
            'metadata' => ['reason' => $e->reason],
        ]);
    }
}
