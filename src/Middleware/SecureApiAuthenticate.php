<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Middleware;

use Closure;
use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Contracts\Authenticator;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;
use SamirEltabal\SecureApi\Exceptions\MechanismNotConfigured;
use SamirEltabal\SecureApi\Models\AuditLog;
use SamirEltabal\SecureApi\Models\Credential;
use Symfony\Component\HttpFoundation\Response;

final class SecureApiAuthenticate
{
    /**
     * Authenticate the request against one or more named mechanisms.
     *
     * Usage:
     *   Route::middleware('secureapi:api_key')->...
     *   Route::middleware('secureapi:jwt,oauth_client')->...
     *
     * Mechanisms are tried in order. The first mechanism whose supports()
     * returns true is the only one that runs authenticate(). If it fails,
     * the request is rejected immediately — no fallthrough to the next
     * mechanism (prevents credential-stuffing across mechanism types).
     *
     * If no mechanism supports the request, 401 is returned.
     */
    public function handle(Request $request, Closure $next, string ...$mechanisms): Response
    {
        foreach ($mechanisms as $mechanism) {
            $authenticator = $this->resolveAuthenticator($mechanism);

            if (! $authenticator->supports($request)) {
                continue;
            }

            try {
                $result = $authenticator->authenticate($request);
                $request->attributes->set('secureapi.credential', $result->credential);

                return $next($request);
            } catch (AuthenticationFailedException $e) {
                $this->writeRejectionAudit($request, $e);

                return response()->json(['message' => 'Unauthenticated.'], 401);
            }
        }

        return response()->json(['message' => 'Unauthenticated.'], 401);
    }

    private function resolveAuthenticator(string $mechanism): Authenticator
    {
        $key = "secureapi.auth.{$mechanism}";

        if (! app()->bound($key)) {
            throw MechanismNotConfigured::forMechanism($mechanism, 'secureapi middleware');
        }

        return app($key);
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

    private function extractRawToken(Request $request): ?string
    {
        $auth = $request->header('Authorization');

        if (is_string($auth) && str_starts_with($auth, 'Bearer ')) {
            return substr($auth, 7);
        }

        $apiKey = $request->header('X-Api-Key');

        return is_string($apiKey) ? $apiKey : null;
    }
}
