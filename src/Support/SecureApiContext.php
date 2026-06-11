<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Support;

use Illuminate\Http\Request;
use SamirEltabal\SecureApi\DTOs\AuthResult;
use SamirEltabal\SecureApi\Models\Credential;

final class SecureApiContext
{
    public static function credential(Request $request): ?Credential
    {
        $value = $request->attributes->get('secureapi.credential');

        return $value instanceof Credential ? $value : null;
    }

    public static function authResult(Request $request): ?AuthResult
    {
        $value = $request->attributes->get('secureapi.auth_result');

        return $value instanceof AuthResult ? $value : null;
    }
}
