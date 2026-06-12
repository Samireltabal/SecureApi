<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Facades;

use Illuminate\Support\Facades\Facade;
use SamirEltabal\SecureApi\DTOs\IssuedCredential;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;

/**
 * @method static Application createApplication(string $name, array<string, mixed> $options = [])
 * @method static Application|null findApplication(string $id)
 * @method static Application|null findApplicationByName(string $name)
 * @method static bool revokeApplication(string $id)
 * @method static IssuedCredential createApiKeyCredential(string $applicationId, array<string, mixed> $options = [])
 * @method static bool revokeCredential(string $credentialId)
 * @method static IssuedCredential rotateApiKeyCredential(string $credentialId)
 * @method static IssuedCredential createHmacCredential(string $applicationId, array<string, mixed> $options = [])
 * @method static IssuedCredential rotateHmacCredential(string $credentialId)
 * @method static IssuedCredential createOauthClientCredential(string $applicationId, array<string, mixed> $options = [])
 * @method static Credential createJwtCredential(string $applicationId, array<string, mixed> $options = [])
 * @method static string issueToken(string $applicationId, array<string, mixed> $options = [])
 * @method static void revokeJwt(string $jti, int|null $ttlSeconds = null)
 *
 * @see \SamirEltabal\SecureApi\SecureApi
 */
class SecureApi extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \SamirEltabal\SecureApi\SecureApi::class;
    }
}
