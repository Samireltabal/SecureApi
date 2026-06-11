<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Models\AuditLog;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Support\JwtManager;

final class OauthTokenController
{
    public function __invoke(Request $request): JsonResponse
    {
        $grantType = $request->input('grant_type');

        if ($grantType === null || $grantType === '') {
            return $this->errorResponse('invalid_request', 400);
        }

        if ($grantType !== 'client_credentials') {
            return $this->errorResponse('unsupported_grant_type', 400);
        }

        [$clientId, $clientSecret] = $this->extractClientCredentials($request);

        if ($clientId === null || $clientSecret === null) {
            return $this->errorResponse('invalid_request', 400);
        }

        $credential = Credential::with('application')
            ->where('type', 'oauth_client')
            ->find($clientId);

        if ($credential === null || ! $this->verifySecret($clientSecret, $credential->secret_hash)) {
            if ($credential !== null) {
                $this->writeFailureAudit($request, $credential, 'invalid_credentials');
            }

            return $this->invalidClient();
        }

        if ($credential->isRevoked() || $credential->isExpired() || ! $credential->is_active) {
            $this->writeFailureAudit($request, $credential, 'credential_invalid');

            return $this->invalidClient();
        }

        $application = $credential->application;

        if ($application === null || ! $application->is_active) {
            $this->writeFailureAudit($request, $credential, 'application_inactive');

            return $this->invalidClient();
        }

        $requestedScopes = $this->parseScopes((string) $request->input('scope', ''));
        $allowedScopes = $credential->scopes;

        if ($requestedScopes !== [] && $allowedScopes !== null) {
            foreach ($requestedScopes as $scope) {
                if (! in_array($scope, $allowedScopes, strict: true)) {
                    return $this->errorResponse('invalid_scope', 400);
                }
            }
        }

        $grantedScopes = $requestedScopes !== [] ? $requestedScopes : ($allowedScopes ?? []);

        $ttl = (int) config('secureapi.oauth.token_ttl', 3600);
        $token = app(JwtManager::class)->issue($credential->id, $grantedScopes, $ttl);

        $credential->update(['last_used_at' => now()]);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => $ttl,
            'scope' => implode(' ', $grantedScopes),
        ])->withHeaders([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    /** @return array{string|null, string|null} */
    private function extractClientCredentials(Request $request): array
    {
        $user = $request->getUser();
        $password = $request->getPassword();

        if (is_string($user) && $user !== '') {
            return [$user, $password ?? ''];
        }

        $clientId = $request->input('client_id');
        $clientSecret = $request->input('client_secret');

        if (is_string($clientId) && $clientId !== '') {
            return [$clientId, is_string($clientSecret) ? $clientSecret : ''];
        }

        return [null, null];
    }

    private function verifySecret(string $provided, ?string $stored): bool
    {
        if ($stored === null) {
            return false;
        }

        return hash_equals($stored, hash('sha256', $provided));
    }

    /** @return list<string> */
    private function parseScopes(string $scope): array
    {
        if ($scope === '') {
            return [];
        }

        return array_values(array_filter(array_map('trim', explode(' ', $scope))));
    }

    private function invalidClient(): JsonResponse
    {
        return $this->errorResponse('invalid_client', 401, ['WWW-Authenticate' => 'Basic realm="SecureApi"']);
    }

    /** @param array<string, string> $headers */
    private function errorResponse(string $error, int $status, array $headers = []): JsonResponse
    {
        return response()->json(['error' => $error], $status, $headers);
    }

    private function writeFailureAudit(Request $request, Credential $credential, string $reason): void
    {
        AuditLog::create([
            'application_id' => $credential->application_id,
            'credential_id' => $credential->id,
            'event' => 'auth.failed',
            'ip_address' => $request->ip(),
            'request_method' => $request->method(),
            'request_path' => $request->getPathInfo(),
            'metadata' => ['reason' => $reason],
        ]);
    }
}
