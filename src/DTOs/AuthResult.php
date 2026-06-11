<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\DTOs;

use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;

final readonly class AuthResult
{
    /** @param array<string> $scopes */
    public function __construct(
        public Application $application,
        public Credential $credential,
        public array $scopes = [],
    ) {}
}
