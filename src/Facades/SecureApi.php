<?php

namespace SamirEltabal\SecureApi\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \SamirEltabal\SecureApi\SecureApi
 */
class SecureApi extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \SamirEltabal\SecureApi\SecureApi::class;
    }
}
