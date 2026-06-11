<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Lcobucci\JWT\Token\RegisteredClaims;
use SamirEltabal\SecureApi\Contracts\Authenticator;
use SamirEltabal\SecureApi\DTOs\AuthResult;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Support\JwtManager;
use Throwable;

final class JwtAuthenticator implements Authenticator
{
    private const REVOCATION_PREFIX = 'secureapi:jwt:revoked:';

    public function __construct(private readonly JwtManager $jwtManager) {}

    public function supports(Request $request): bool
    {
        $auth = (string) $request->header('Authorization', '');

        if (! str_starts_with($auth, 'Bearer ')) {
            return false;
        }

        $token = substr($auth, 7);

        return str_contains($token, '.');
    }

    public function authenticate(Request $request): AuthResult
    {
        $auth = (string) $request->header('Authorization', '');
        $token = substr($auth, 7);

        try {
            $parsed = $this->jwtManager->parse($token);
            $this->jwtManager->validate($parsed);
        } catch (Throwable $e) {
            if ($e instanceof AuthenticationFailedException) {
                throw $e;
            }
            throw AuthenticationFailedException::invalidToken();
        }

        $credentialId = $parsed->claims()->get(RegisteredClaims::SUBJECT);

        if (! is_string($credentialId) || $credentialId === '') {
            throw AuthenticationFailedException::invalidCredential();
        }

        $credential = Credential::with('application')
            ->whereIn('type', ['jwt', 'oauth_client'])
            ->find($credentialId);

        if ($credential === null) {
            throw AuthenticationFailedException::invalidCredential();
        }

        if ($credential->isRevoked()) {
            throw AuthenticationFailedException::revoked();
        }

        if ($credential->isExpired()) {
            throw AuthenticationFailedException::expired();
        }

        $jti = $parsed->claims()->get(RegisteredClaims::ID);

        if (is_string($jti) && $jti !== '' && Cache::has(self::REVOCATION_PREFIX.$jti)) {
            throw AuthenticationFailedException::invalidToken('jti_revoked');
        }

        /** @var Application $application */
        $application = $credential->application;

        if (! $application->is_active) {
            throw AuthenticationFailedException::applicationInactive();
        }

        $scopes = $parsed->claims()->has('scopes')
            ? (array) $parsed->claims()->get('scopes')
            : ($credential->scopes ?? []);

        $credential->update(['last_used_at' => now()]);

        return new AuthResult($application, $credential, $scopes);
    }
}
