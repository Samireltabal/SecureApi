<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Support;

final class CertificateFingerprint
{
    public static function compute(string $pemCert): ?string
    {
        $result = @openssl_x509_fingerprint($pemCert, 'sha256', false);

        return $result === false ? null : $result;
    }
}
