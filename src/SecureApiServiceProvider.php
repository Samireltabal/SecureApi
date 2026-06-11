<?php

namespace SamirEltabal\SecureApi;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use SamirEltabal\SecureApi\Commands\SecureApiCommand;

class SecureApiServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('secureapi')
            ->hasConfigFile()
            ->hasViews()
            ->hasMigration('create_secureapi_table')
            ->hasCommand(SecureApiCommand::class);
    }
}
