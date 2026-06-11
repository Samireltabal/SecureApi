<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use SamirEltabal\SecureApi\Auth\ApiKeyAuthenticator;
use SamirEltabal\SecureApi\Auth\HmacAuthenticator;
use SamirEltabal\SecureApi\Auth\JwtAuthenticator;
use SamirEltabal\SecureApi\Auth\MtlsAuthenticator;
use SamirEltabal\SecureApi\Auth\SecureApiGuard;
use SamirEltabal\SecureApi\Commands\App\AppSettingsCommand;
use SamirEltabal\SecureApi\Commands\App\CreateAppCommand;
use SamirEltabal\SecureApi\Commands\App\RevokeAppCommand;
use SamirEltabal\SecureApi\Commands\Credential\CreateCredentialCommand;
use SamirEltabal\SecureApi\Commands\Credential\RevokeCredentialCommand;
use SamirEltabal\SecureApi\Commands\Credential\RotateCredentialCommand;
use SamirEltabal\SecureApi\Commands\Jwt\GenerateKeysCommand;
use SamirEltabal\SecureApi\Commands\Mtls\MtlsRegisterCommand;
use SamirEltabal\SecureApi\Http\Controllers\OauthTokenController;
use SamirEltabal\SecureApi\Middleware\AllowedIpsMiddleware;
use SamirEltabal\SecureApi\Middleware\AuditMiddleware;
use SamirEltabal\SecureApi\Middleware\ScopesMiddleware;
use SamirEltabal\SecureApi\Middleware\ThrottleMiddleware;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\Support\HmacSigner;
use SamirEltabal\SecureApi\Support\JwtManager;
use SamirEltabal\SecureApi\Support\NonceStore;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SecureApiServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('secureapi')
            ->hasConfigFile()
            ->discoversMigrations()
            ->hasCommands([
                CreateAppCommand::class,
                RevokeAppCommand::class,
                AppSettingsCommand::class,
                CreateCredentialCommand::class,
                RevokeCredentialCommand::class,
                RotateCredentialCommand::class,
                GenerateKeysCommand::class,
                MtlsRegisterCommand::class,
            ]);
    }

    public function packageBooted(): void
    {
        Auth::extend('secureapi', function ($app, string $name, array $config) {
            return new SecureApiGuard($name, $config, $app);
        });

        $this->registerMiddlewareAliases();
        $this->registerRequestMacro();
        $this->registerOauthEndpoint();
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(SecureApi::class, fn () => new SecureApi);
        $this->app->alias(SecureApi::class, 'secureapi');

        $this->app->singleton(JwtManager::class, fn () => new JwtManager((array) config('secureapi.jwt', [])));

        $this->app->bind('secureapi.auth.api_key', fn () => new ApiKeyAuthenticator);
        $this->app->bind('secureapi.auth.hmac', fn () => new HmacAuthenticator(new HmacSigner, new NonceStore));
        $this->app->bind('secureapi.auth.jwt', fn ($app) => new JwtAuthenticator($app->make(JwtManager::class)));
        $this->app->bind('secureapi.auth.mtls', fn () => new MtlsAuthenticator);
    }

    private function registerMiddlewareAliases(): void
    {
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('secureapi.scopes', ScopesMiddleware::class);
        $router->aliasMiddleware('secureapi.scope', ScopesMiddleware::class);
        $router->aliasMiddleware('secureapi.allow_ips', AllowedIpsMiddleware::class);
        $router->aliasMiddleware('secureapi.throttle', ThrottleMiddleware::class);
        $router->aliasMiddleware('secureapi.audit', AuditMiddleware::class);
    }

    private function registerRequestMacro(): void
    {
        Request::macro('apiCredential', function (): ?Credential {
            /** @var Request $this */
            return $this->attributes->get('secureapi.credential');
        });
    }

    private function registerOauthEndpoint(): void
    {
        if (! (bool) config('secureapi.oauth.enabled', true)) {
            return;
        }

        $prefix = rtrim((string) config('secureapi.oauth.path_prefix', 'secureapi/oauth'), '/');

        RateLimiter::for('secureapi-oauth-token', fn (Request $request) => Limit::perMinute(
            (int) config('secureapi.oauth.rate_limit_per_minute', 10)
        )->by($request->ip()));

        $this->app->make(Router::class)
            ->post($prefix.'/token', OauthTokenController::class)
            ->name('secureapi.oauth.token')
            ->middleware('throttle:secureapi-oauth-token');
    }
}
