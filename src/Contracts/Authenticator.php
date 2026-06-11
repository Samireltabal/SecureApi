<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Contracts;

use Illuminate\Http\Request;
use SamirEltabal\SecureApi\DTOs\AuthResult;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;

interface Authenticator
{
    public function supports(Request $request): bool;

    /**
     * @throws AuthenticationFailedException when credentials are presented but rejected
     */
    public function authenticate(Request $request): AuthResult;
}
