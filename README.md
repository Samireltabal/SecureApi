# SecureApi — Laravel API Authentication

[![Latest Version on Packagist](https://img.shields.io/packagist/v/samireltabal/secureapi.svg?style=flat-square)](https://packagist.org/packages/samireltabal/secureapi)
[![GitHub Tests Action Status](https://github.com/samireltabal/secureapi/actions/workflows/run-tests.yml/badge.svg)](https://github.com/samireltabal/secureapi/actions?query=workflow%3Arun-tests+branch%3Amain)
[![PHPStan](https://github.com/samireltabal/secureapi/actions/workflows/phpstan.yml/badge.svg)](https://github.com/samireltabal/secureapi/actions/workflows/phpstan.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/samireltabal/secureapi.svg?style=flat-square)](https://packagist.org/packages/samireltabal/secureapi)

A plug-in authentication package for Laravel 12+ that provides five API-security mechanisms through a single unified guard driver. Mix and match mechanisms per route group; each mechanism is independently testable and configurable.

**Mechanisms**

| Mechanism | Guard token | Use case |
|-----------|-------------|----------|
| `api_key` | `Bearer sk_…` | Server-to-server, mobile clients |
| `hmac` | HMAC-SHA256 signed request | Webhook producers, high-integrity integrations |
| `jwt` | RS256 / HS256 Bearer JWT | External IdPs, delegated auth |
| `oauth2` | Built-in client-credentials flow | Machine-to-machine OAuth2 |
| `mtls` | Proxy-forwarded client certificate | Zero-trust service mesh (opt-in, fail-loud) |

All mechanisms share: scoped credentials, per-application IP allow-listing, per-credential rate limiting, tamper-evident audit logs, and replay protection for HMAC.

---

## Requirements

- PHP 8.3+
- Laravel 12 or 13

## Installation

```bash
composer require samireltabal/secureapi
```

Publish and run the migrations:

```bash
php artisan vendor:publish --tag="secureapi-migrations"
php artisan migrate
```

Publish the config (optional — sensible defaults ship out of the box):

```bash
php artisan vendor:publish --tag="secureapi-config"
```

---

## Quick Start

### 1. Register a guard

```php
// config/auth.php
'guards' => [
    'api' => [
        'driver'     => 'secureapi',
        'mechanisms' => ['api_key', 'jwt'],   // tried in order, first match wins
    ],
],
```

### 2. Create an application and credential

```php
use SamirEltabal\SecureApi\Facades\SecureApi;

$app        = SecureApi::createApplication('My Service');
$credential = SecureApi::createApiKeyCredential($app->id);

// $credential->plaintextKey — the full sk_…_… token; shown once
```

### 3. Protect routes

```php
Route::middleware('auth:api')->group(function () {
    Route::get('/protected', fn () => response()->json(['ok' => true]));
});
```

### 4. Call from a client

```
GET /protected HTTP/1.1
Authorization: Bearer sk_<public>_<secret>
```

---

## Mechanisms

### API Key

Bearer token in the format `sk_<26-char-public>_<64-char-secret>`.

```php
$credential = SecureApi::createApiKeyCredential($appId, [
    'name'    => 'mobile-client',
    'scopes'  => ['read', 'write'],
    'expires' => now()->addYear(),
]);
```

See [docs/api-key.md](docs/api-key.md).

### HMAC Request Signing

Every request is signed with `HMAC-SHA256` over `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH`.

Required headers: `X-SecureApi-Signature`, `X-SecureApi-Timestamp`, `X-SecureApi-Nonce`.

```php
$credential = SecureApi::createHmacCredential($appId);
// $credential->secret — shared secret; shown once
```

See [docs/hmac.md](docs/hmac.md) for the signing algorithm and replay-window config.

### JWT (RS256 / HS256)

Validates externally-issued JWTs against your public key (RS256 default) or a shared secret (HS256).

```env
SECUREAPI_JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..."
SECUREAPI_JWT_ISSUER=https://auth.example.com
```

```php
// config/auth.php — a JWT-only guard
'guards' => [
    'jwt-api' => ['driver' => 'secureapi', 'mechanisms' => ['jwt']],
],
```

See [docs/jwt.md](docs/jwt.md).

### OAuth2 Client Credentials

Built-in `POST /secureapi/oauth/token` endpoint; standard `client_credentials` grant.

```php
$credential = SecureApi::createOauthClientCredential($appId, [
    'name' => 'partner-service',
]);
// $credential->plaintextKey — the client_secret
```

```
POST /secureapi/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<credential_id>
&client_secret=<plaintextKey>
```

See [docs/oauth2.md](docs/oauth2.md).

### mTLS (mutual TLS)

Opt-in, fail-loud. Your TLS-terminating proxy (nginx, Envoy) verifies the client certificate and forwards the result in headers. SecureApi validates the forwarded certificate fingerprint against a stored SHA-256 hash.

```env
SECUREAPI_MTLS_ENABLED=true
SECUREAPI_MTLS_TRUSTED_PROXIES=10.0.0.1,172.16.0.0/12
```

```php
// config/secureapi.php
'mtls' => [
    'enabled'          => env('SECUREAPI_MTLS_ENABLED', false),
    'trusted_proxies'  => explode(',', env('SECUREAPI_MTLS_TRUSTED_PROXIES', '')),
    'verify_header'    => 'ssl-client-verify',
    'cert_header'      => 'ssl-client-cert',
],
```

Register a client certificate:

```bash
php artisan secureapi:mtls:register my-app-name /path/to/client.crt
```

See [docs/mtls.md](docs/mtls.md) for nginx CA setup and docker playground instructions.

---

## Artisan Commands

| Command | Description |
|---------|-------------|
| `secureapi:app:create` | Create an application |
| `secureapi:app:list` | List all applications |
| `secureapi:app:revoke {id}` | Revoke an application |
| `secureapi:key:issue {app}` | Issue an API key credential |
| `secureapi:key:revoke {id}` | Revoke a credential |
| `secureapi:jwt:generate-keys` | Generate RS256 key pair |
| `secureapi:mtls:register {app} {cert}` | Register a client certificate for mTLS |

---

## Configuration Reference

```php
// config/secureapi.php (published)

'table_prefix' => env('SECUREAPI_TABLE_PREFIX', 'secure_api_'),

'oauth' => [
    'enabled'              => true,
    'path_prefix'          => 'secureapi/oauth',
    'token_ttl'            => 3600,
    'rate_limit_per_minute'=> 10,
],

'mtls' => [
    'enabled'          => false,
    'trusted_proxies'  => [],
    'cert_header'      => 'ssl-client-cert',
    'verify_header'    => 'ssl-client-verify',
],

'jwt' => [
    'algorithm'  => 'RS256',              // 'RS256' or 'HS256'
    'public_key' => env('SECUREAPI_JWT_PUBLIC_KEY'),
    'private_key'=> env('SECUREAPI_JWT_PRIVATE_KEY'),
    'key_id'     => env('SECUREAPI_JWT_KEY_ID'),
    'issuer'     => env('SECUREAPI_JWT_ISSUER', env('APP_URL')),
    'audience'   => env('SECUREAPI_JWT_AUDIENCE'),
    'ttl'        => 3600,
],

'audit' => [
    'retention_days' => 90,     // null = keep forever; pruned by model:prune
],

'rate_limit' => [
    'default_per_minute' => null,   // null = unlimited
],

'hmac' => [
    'timestamp_window' => 300,  // seconds; requests older than ±window are rejected
],

'replay' => [
    'cache_store' => null,      // null = app default; set 'redis' for dedicated store
],
```

---

## Scopes, Rate Limiting & Audit

See [docs/scopes-rate-limiting-audit.md](docs/scopes-rate-limiting-audit.md).

---

## Security Model

- All secrets are **bcrypt-hashed** at rest (API keys, HMAC secrets, OAuth client secrets). Plaintext is shown once on creation and never stored.
- HMAC nonces are tracked in the Laravel cache for the replay window; use a shared cache (Redis) in multi-node deployments.
- mTLS is **fail-loud by design**: if `secureapi.mtls.enabled` is `true` but `trusted_proxies` is empty (or vice versa), the mechanism throws `MtlsNotEnabled` (HTTP 500) rather than silently returning 401. This surfaces infrastructure misconfiguration immediately.
- JWT `alg:none` tokens are unconditionally rejected.
- IP allow-listing is enforced via `Symfony\Component\HttpFoundation\IpUtils` (supports IPv4, IPv6, and CIDR ranges).

---

## Testing

```bash
composer test          # Pest suite
composer analyse       # PHPStan level 8
composer format        # Laravel Pint
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security Vulnerabilities

Please review [our security policy](../../security/policy) to report security vulnerabilities responsibly.

## Credits

- [Samir M. Eltabal](https://github.com/Samireltabal)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [LICENSE.md](LICENSE.md) for more information.
