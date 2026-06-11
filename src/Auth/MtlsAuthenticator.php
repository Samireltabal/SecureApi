<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Auth;

use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Contracts\Authenticator;
use SamirEltabal\SecureApi\DTOs\AuthResult;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;
use SamirEltabal\SecureApi\Exceptions\MtlsNotEnabled;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Support\CertificateFingerprint;
use Symfony\Component\HttpFoundation\IpUtils;

final class MtlsAuthenticator implements Authenticator
{
    public function supports(Request $request): bool
    {
        $enabled = (bool) config('secureapi.mtls.enabled', false);
        $proxies = (array) config('secureapi.mtls.trusted_proxies', []);

        // Fail-loud: if disabled or unconfigured, always "support" so authenticate()
        // runs and throws MtlsNotEnabled — prevents silent 401 hiding a config error.
        if (! $enabled || empty($proxies)) {
            return true;
        }

        $verifyHeader = (string) config('secureapi.mtls.verify_header', 'ssl-client-verify');

        return $request->hasHeader($verifyHeader);
    }

    public function authenticate(Request $request): AuthResult
    {
        $enabled = (bool) config('secureapi.mtls.enabled', false);
        $proxies = (array) config('secureapi.mtls.trusted_proxies', []);

        if (! $enabled) {
            throw MtlsNotEnabled::disabled();
        }

        if (empty($proxies)) {
            throw MtlsNotEnabled::noTrustedProxies();
        }

        // Only accept from known proxy IPs — guards against header spoofing.
        $serverRemoteAddr = $request->server('REMOTE_ADDR');
        $remoteIp = is_string($serverRemoteAddr) ? $serverRemoteAddr : '';
        if (! IpUtils::checkIp($remoteIp, $proxies)) {
            throw AuthenticationFailedException::invalidCredential();
        }

        $verifyHeader = (string) config('secureapi.mtls.verify_header', 'ssl-client-verify');
        if ($request->header($verifyHeader) !== 'SUCCESS') {
            throw AuthenticationFailedException::invalidCredential();
        }

        $certHeader = (string) config('secureapi.mtls.cert_header', 'ssl-client-cert');
        $rawCert = $request->header($certHeader);

        if (! is_string($rawCert) || $rawCert === '') {
            throw AuthenticationFailedException::invalidCredential();
        }

        $pem = urldecode($rawCert);
        $fingerprint = CertificateFingerprint::compute($pem);

        if ($fingerprint === null) {
            throw AuthenticationFailedException::invalidCredential();
        }

        $credential = Credential::with('application')
            ->where('type', 'mtls_cert')
            ->where('certificate_fingerprint', $fingerprint)
            ->first();

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

        $credential->update(['last_used_at' => now()]);

        return new AuthResult($application, $credential, $credential->scopes ?? []);
    }
}
