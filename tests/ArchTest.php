<?php

use Illuminate\Support\Facades\Facade;

arch('it will not use debugging functions')
    ->expect(['dd', 'dump', 'ray'])
    ->each->not->toBeUsed();

arch('all src files declare strict types')
    ->expect('SamirEltabal\SecureApi')
    ->toUseStrictTypes();

arch('authenticators do not use facades')
    ->expect('SamirEltabal\SecureApi\Auth')
    ->not->toUse(Facade::class);

arch('auth classes are final')
    ->expect('SamirEltabal\SecureApi\Auth')
    ->toBeFinal();
