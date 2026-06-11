<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Orchestra\Testbench\TestCase as Orchestra;
use SamirEltabal\SecureApi\SecureApiServiceProvider;

class TestCase extends Orchestra
{
    private static ?string $jwtPrivateKey = null;

    private static ?string $jwtPublicKey = null;

    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'SamirEltabal\\SecureApi\\Database\\Factories\\'.class_basename($modelName).'Factory'
        );
    }

    protected function getPackageProviders($app): array
    {
        return [
            SecureApiServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app): void
    {
        config()->set('database.default', 'testing');
        config()->set('app.key', 'base64:'.base64_encode(str_repeat('x', 32)));

        $app['db']->connection()->statement('PRAGMA foreign_keys = ON;');

        if (static::$jwtPrivateKey === null) {
            $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($res, static::$jwtPrivateKey);
            static::$jwtPublicKey = openssl_pkey_get_details($res)['key'];
        }

        config()->set('secureapi.jwt', [
            'algorithm' => 'RS256',
            'private_key' => static::$jwtPrivateKey,
            'public_key' => static::$jwtPublicKey,
            'key_id' => 'test-key-1',
            'issuer' => 'http://localhost',
            'audience' => 'http://localhost',
            'ttl' => 3600,
        ]);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }
}
