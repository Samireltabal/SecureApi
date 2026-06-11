<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Exceptions;

use RuntimeException;

final class MechanismNotConfigured extends RuntimeException
{
    public static function forMechanism(string $mechanism, string $guardName): self
    {
        return new self(
            "SecureApi mechanism [{$mechanism}] requested by guard [{$guardName}] is not registered. ".
            'Ensure the mechanism service provider is loaded or the mechanism key is correct.'
        );
    }
}
