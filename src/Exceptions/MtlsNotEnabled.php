<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Exceptions;

use RuntimeException;

final class MtlsNotEnabled extends RuntimeException
{
    public static function forGuard(string $guardName): self
    {
        return new self(
            "Guard [{$guardName}] references the mtls mechanism but mTLS is disabled. ".
            'Set secureapi.mtls.enabled=true and provide at least one trusted proxy to enable it.'
        );
    }

    public static function disabled(): self
    {
        return new self(
            'mTLS mechanism is referenced but secureapi.mtls.enabled is false. '.
            'Set secureapi.mtls.enabled=true and provide at least one trusted proxy.'
        );
    }

    public static function noTrustedProxies(): self
    {
        return new self(
            'mTLS mechanism is enabled but secureapi.mtls.trusted_proxies is empty. '.
            'Add at least one trusted proxy IP or CIDR range.'
        );
    }
}
