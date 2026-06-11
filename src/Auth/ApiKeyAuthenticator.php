<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Auth;

use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Contracts\Authenticator;
use SamirEltabal\SecureApi\DTOs\AuthResult;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;

final class ApiKeyAuthenticator implements Authenticator
{
    // Token format: sk_<26-char ULID>_<64-char hex secret>
    private const TOKEN_LENGTH = 94;

    private const KEY_ID_OFFSET = 3;

    private const KEY_ID_LENGTH = 26;

    private const SECRET_OFFSET = 30;

    public function supports(Request $request): bool
    {
        $token = $this->extractToken($request);

        return $token !== null
            && strlen($token) === self::TOKEN_LENGTH
            && str_starts_with($token, 'sk_')
            && $token[29] === '_';
    }

    public function authenticate(Request $request): AuthResult
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            throw AuthenticationFailedException::invalidCredential();
        }

        $keyId = substr($token, self::KEY_ID_OFFSET, self::KEY_ID_LENGTH);
        $rawSecret = substr($token, self::SECRET_OFFSET);

        $credential = Credential::with('application')
            ->where('type', 'api_key')
            ->find($keyId);

        if ($credential === null || ! hash_equals($credential->secret_hash ?? '', hash('sha256', $rawSecret))) {
            throw AuthenticationFailedException::invalidCredential();
        }

        if ($credential->isRevoked()) {
            throw AuthenticationFailedException::revoked();
        }

        if ($credential->isExpired()) {
            throw AuthenticationFailedException::expired();
        }

        /** @var Application $application */
        $application = $credential->application;

        if (! $application->is_active) {
            throw AuthenticationFailedException::applicationInactive();
        }

        $credential->update(['last_used_at' => now()]);

        return new AuthResult($application, $credential, $credential->scopes ?? []);
    }

    private function extractToken(Request $request): ?string
    {
        $header = $request->header('Authorization', '');

        if (str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        $apiKey = $request->header('X-Api-Key');

        return is_string($apiKey) ? $apiKey : null;
    }
}
