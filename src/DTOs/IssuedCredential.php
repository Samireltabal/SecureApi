<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\DTOs;

use SamirEltabal\SecureApi\Models\Credential;

final readonly class IssuedCredential
{
    public function __construct(
        public Credential $credential,
        public string $plaintextKey,
    ) {}
}
