<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Table Prefix
    |--------------------------------------------------------------------------
    | All SecureApi tables are prefixed so they do not collide with your app's
    | tables. Change this BEFORE running migrations. Changing it after requires
    | renaming tables manually.
    */
    'table_prefix' => env('SECUREAPI_TABLE_PREFIX', 'secure_api_'),

    /*
    |--------------------------------------------------------------------------
    | OAuth2 Token Endpoint
    |--------------------------------------------------------------------------
    | Enable/disable the built-in token endpoint and configure its URL prefix.
    */
    'oauth' => [
        'enabled' => true,
        'path_prefix' => 'secureapi/oauth',
        'token_ttl' => 3600,
        'rate_limit_per_minute' => 10,
    ],

    /*
    |--------------------------------------------------------------------------
    | mTLS (mutual TLS) — opt-in, default disabled
    |--------------------------------------------------------------------------
    | Enable when your infrastructure terminates TLS and forwards the verified
    | client certificate in request headers. BOTH enabled=true AND a non-empty
    | trusted_proxies list are required; if either is missing the mTLS mechanism
    | throws MtlsNotEnabled rather than silently passing or failing auth.
    */
    'mtls' => [
        'enabled' => false,
        'trusted_proxies' => [],
        'cert_header' => 'ssl-client-cert',
        'verify_header' => 'ssl-client-verify',
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT
    |--------------------------------------------------------------------------
    | RS256 by default. HS256 is supported for environments that cannot manage
    | asymmetric key pairs. alg=none is always rejected.
    */
    'jwt' => [
        'algorithm' => 'RS256',
        'public_key' => env('SECUREAPI_JWT_PUBLIC_KEY'),
        'private_key' => env('SECUREAPI_JWT_PRIVATE_KEY'),
        'key_id' => env('SECUREAPI_JWT_KEY_ID'),
        'issuer' => env('SECUREAPI_JWT_ISSUER', env('APP_URL')),
        'audience' => env('SECUREAPI_JWT_AUDIENCE'),
        'ttl' => 3600,
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit Logs
    |--------------------------------------------------------------------------
    | retention_days: number of days to keep audit records; null = keep forever.
    | Pruning happens via `php artisan model:prune` using Laravel's MassPrunable.
    */
    'audit' => [
        'retention_days' => 90,
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting Defaults
    |--------------------------------------------------------------------------
    | Applied when a credential has no per-credential override. null = unlimited.
    */
    'rate_limit' => [
        'default_per_minute' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | HMAC Request Signing
    |--------------------------------------------------------------------------
    | timestamp_window: maximum age of a signed request in seconds (±window).
    */
    'hmac' => [
        'timestamp_window' => 300,
    ],

    /*
    |--------------------------------------------------------------------------
    | Replay Protection
    |--------------------------------------------------------------------------
    | cache_store: null = use the application default; set to a named store
    | (e.g. 'redis') if you want nonce tracking separate from the main cache.
    */
    'replay' => [
        'cache_store' => null,
    ],

];
