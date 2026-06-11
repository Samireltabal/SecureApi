<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi;

use Illuminate\Support\Facades\Cache;
use SamirEltabal\SecureApi\DTOs\IssuedCredential;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Support\JwtManager;

final class SecureApi
{
    /** @param array<string, mixed> $options */
    public function createApplication(string $name, array $options = []): Application
    {
        $application = Application::create([
            'name' => $name,
            'description' => $options['description'] ?? null,
            'allowed_ips' => $options['allowed_ips'] ?? null,
            'rate_limit_per_minute' => $options['rate_limit_per_minute'] ?? null,
            'is_active' => true,
        ]);

        if (! empty($options['settings'])) {
            foreach ($options['settings'] as $key => $value) {
                $application->setSetting($key, $value);
            }
        }

        return $application;
    }

    public function findApplication(string $id): ?Application
    {
        return Application::find($id);
    }

    public function findApplicationByName(string $name): ?Application
    {
        return Application::where('name', $name)->first();
    }

    public function revokeApplication(string $id): bool
    {
        $application = Application::find($id);

        if ($application === null) {
            return false;
        }

        $application->update([
            'is_active' => false,
            'revoked_at' => now(),
        ]);

        return true;
    }

    /** @param array<string, mixed> $options */
    public function createApiKeyCredential(string $applicationId, array $options = []): IssuedCredential
    {
        $rawSecret = bin2hex(random_bytes(32));

        $credential = Credential::create([
            'application_id' => $applicationId,
            'type' => 'api_key',
            'name' => $options['name'] ?? null,
            'secret_hash' => hash('sha256', $rawSecret),
            'scopes' => $options['scopes'] ?? null,
            'expires_at' => $options['expires_at'] ?? null,
            'is_active' => true,
        ]);

        return new IssuedCredential($credential, "sk_{$credential->id}_{$rawSecret}");
    }

    public function revokeCredential(string $credentialId): bool
    {
        $credential = Credential::find($credentialId);

        if ($credential === null) {
            return false;
        }

        $credential->update([
            'is_active' => false,
            'revoked_at' => now(),
        ]);

        return true;
    }

    public function rotateApiKeyCredential(string $credentialId): IssuedCredential
    {
        $credential = Credential::findOrFail($credentialId);

        $rawSecret = bin2hex(random_bytes(32));
        $credential->update(['secret_hash' => hash('sha256', $rawSecret)]);

        return new IssuedCredential($credential->fresh() ?? $credential, "sk_{$credential->id}_{$rawSecret}");
    }

    /** @param array<string, mixed> $options */
    public function createHmacCredential(string $applicationId, array $options = []): IssuedCredential
    {
        $rawSecret = bin2hex(random_bytes(32));

        $credential = Credential::create([
            'application_id' => $applicationId,
            'type' => 'hmac',
            'name' => $options['name'] ?? null,
            'secret_encrypted' => $rawSecret,
            'scopes' => $options['scopes'] ?? null,
            'expires_at' => $options['expires_at'] ?? null,
            'is_active' => true,
        ]);

        return new IssuedCredential($credential, $rawSecret);
    }

    public function rotateHmacCredential(string $credentialId): IssuedCredential
    {
        $credential = Credential::findOrFail($credentialId);

        $rawSecret = bin2hex(random_bytes(32));
        $credential->update(['secret_encrypted' => $rawSecret]);

        return new IssuedCredential($credential->fresh() ?? $credential, $rawSecret);
    }

    /** @param array<string, mixed> $options */
    public function createOauthClientCredential(string $applicationId, array $options = []): IssuedCredential
    {
        $rawSecret = bin2hex(random_bytes(32));

        $credential = Credential::create([
            'application_id' => $applicationId,
            'type' => 'oauth_client',
            'name' => $options['name'] ?? null,
            'secret_hash' => hash('sha256', $rawSecret),
            'scopes' => $options['scopes'] ?? null,
            'expires_at' => $options['expires_at'] ?? null,
            'is_active' => true,
        ]);

        return new IssuedCredential($credential, $rawSecret);
    }

    /** @param array<string, mixed> $options */
    public function createJwtCredential(string $applicationId, array $options = []): Credential
    {
        return Credential::create([
            'application_id' => $applicationId,
            'type' => 'jwt',
            'name' => $options['name'] ?? null,
            'scopes' => $options['scopes'] ?? null,
            'expires_at' => $options['expires_at'] ?? null,
            'is_active' => true,
        ]);
    }

    /** @param array<string,mixed> $options */
    public function issueToken(string $applicationId, array $options = []): string
    {
        $credentialId = $options['credential_id'] ?? null;

        if (is_string($credentialId) && $credentialId !== '') {
            $credential = Credential::where('application_id', $applicationId)
                ->where('type', 'jwt')
                ->where('is_active', true)
                ->whereNull('revoked_at')
                ->find($credentialId);
        } else {
            $credential = Credential::where('application_id', $applicationId)
                ->where('type', 'jwt')
                ->where('is_active', true)
                ->whereNull('revoked_at')
                ->first();
        }

        if ($credential === null) {
            throw new \RuntimeException("No active JWT credential found for application {$applicationId}.");
        }

        $manager = app(JwtManager::class);

        return $manager->issue(
            $credential->id,
            $credential->scopes ?? [],
            isset($options['ttl']) ? (int) $options['ttl'] : null,
            $options['extra_claims'] ?? [],
        );
    }

    public function revokeJwt(string $jti, ?int $ttlSeconds = null): void
    {
        $ttl = $ttlSeconds ?? (int) config('secureapi.jwt.ttl', 3600);
        Cache::put('secureapi:jwt:revoked:'.$jti, true, $ttl);
    }
}
