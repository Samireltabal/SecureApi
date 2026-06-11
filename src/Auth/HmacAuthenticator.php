<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Auth;

use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Contracts\Authenticator;
use SamirEltabal\SecureApi\DTOs\AuthResult;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Support\HmacSigner;
use SamirEltabal\SecureApi\Support\NonceStore;

final class HmacAuthenticator implements Authenticator
{
    private const KEY_ID_HEADER = 'X-SecureApi-Key-Id';

    private const TIMESTAMP_HEADER = 'X-SecureApi-Timestamp';

    private const NONCE_HEADER = 'X-SecureApi-Nonce';

    private const SIGNATURE_HEADER = 'X-SecureApi-Signature';

    public function __construct(
        private readonly HmacSigner $signer,
        private readonly NonceStore $nonceStore,
    ) {}

    public function supports(Request $request): bool
    {
        return $request->hasHeader(self::SIGNATURE_HEADER);
    }

    public function authenticate(Request $request): AuthResult
    {
        $keyId = $request->header(self::KEY_ID_HEADER);
        $timestamp = $request->header(self::TIMESTAMP_HEADER);
        $nonce = $request->header(self::NONCE_HEADER);
        $signature = $request->header(self::SIGNATURE_HEADER);

        if (! is_string($keyId) || ! is_string($timestamp) || ! is_string($nonce) || ! is_string($signature)) {
            throw AuthenticationFailedException::invalidCredential();
        }

        $window = (int) config('secureapi.hmac.timestamp_window', 300);

        if (abs(time() - (int) $timestamp) > $window) {
            throw AuthenticationFailedException::timestampOutOfWindow();
        }

        $credential = Credential::with('application')
            ->where('type', 'hmac')
            ->find($keyId);

        if ($credential === null) {
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

        $secret = $credential->secret_encrypted;

        if (! is_string($secret)) {
            throw AuthenticationFailedException::invalidCredential();
        }

        $stringToSign = $this->signer->buildStringToSign(
            $request->method(),
            $request->getPathInfo(),
            $timestamp,
            $nonce,
            $request->getContent(),
        );

        if (! $this->signer->verify($stringToSign, $secret, $signature)) {
            throw AuthenticationFailedException::invalidCredential();
        }

        if (! $this->nonceStore->consume($keyId, $nonce, $window * 2)) {
            throw AuthenticationFailedException::replayed();
        }

        $credential->update(['last_used_at' => now()]);

        return new AuthResult($application, $credential, $credential->scopes ?? []);
    }
}
