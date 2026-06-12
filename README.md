# SecureApi — Laravel API Authentication

[![Latest Version on Packagist](https://img.shields.io/packagist/v/samireltabal/secureapi.svg?style=flat-square)](https://packagist.org/packages/samireltabal/secureapi)
[![GitHub Tests Action Status](https://github.com/samireltabal/secureapi/actions/workflows/run-tests.yml/badge.svg)](https://github.com/samireltabal/secureapi/actions?query=workflow%3Arun-tests+branch%3Amain)
[![PHPStan](https://github.com/samireltabal/secureapi/actions/workflows/phpstan.yml/badge.svg)](https://github.com/samireltabal/secureapi/actions/workflows/phpstan.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/samireltabal/secureapi.svg?style=flat-square)](https://packagist.org/packages/samireltabal/secureapi)

A plug-in authentication package for Laravel 12+ that provides five API-security mechanisms through a single standalone middleware. Mix and match mechanisms per route group; each mechanism is independently testable and configurable.

**Mechanisms**

| Mechanism | Token / Transport | Use case |
|-----------|-------------------|----------|
| `api_key` | `Bearer sk_…` | Server-to-server, mobile clients |
| `hmac` | HMAC-SHA256 signed request | Webhook producers, high-integrity integrations |
| `jwt` | RS256 / HS256 Bearer JWT | External IdPs, delegated auth |
| `oauth_client` | Built-in client-credentials flow | Machine-to-machine OAuth2 |
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

### 1. Create an application and credential

```php
use SamirEltabal\SecureApi\Facades\SecureApi;

$app        = SecureApi::createApplication('My Service');
$credential = SecureApi::createApiKeyCredential($app->id);

// $credential->plaintextKey — the full sk_…_… token; shown once, never stored in plaintext
```

### 2. Protect routes

Add the `secureapi` middleware and pass the mechanism(s) you want to accept. Mechanisms are tried in order — the first one whose token format matches wins:

```php
// Single mechanism
Route::middleware('secureapi:api_key')->group(function () {
    Route::get('/protected', fn () => response()->json(['ok' => true]));
});

// Multiple accepted mechanisms (tried in order)
Route::middleware('secureapi:jwt,api_key')->group(function () {
    Route::get('/flexible', fn () => response()->json(['ok' => true]));
});
```

### 3. Call from a client

```
GET /protected HTTP/1.1
Authorization: Bearer sk_<public>_<secret>
```

### 4. (Optional) Check scopes inside a controller

```php
use SamirEltabal\SecureApi\Facades\SecureApi;

Route::middleware(['secureapi:api_key', 'secureapi.scopes:read'])->group(function () {
    Route::get('/data', fn () => response()->json(['data' => []]));
});
```

---

## Mechanisms

### API Key

Bearer token in the format `sk_<26-char-public>_<64-char-secret>`. The secret is stored as a SHA-256 hash; the plaintext is shown once on creation.

```php
$credential = SecureApi::createApiKeyCredential($appId, [
    'name'    => 'mobile-client',
    'scopes'  => ['read', 'write'],
    'expires' => now()->addYear(),
]);
// $credential->plaintextKey  — Bearer token to send in Authorization header
// $credential->credential    — Eloquent Credential model
```

**Rotate** when a key may have been compromised:

```php
$new = SecureApi::rotateApiKeyCredential($credentialId);
// $new->plaintextKey — new token; old key stops working immediately
```

Full details: [docs/api-key.md](https://github.com/samireltabal/secureapi/blob/main/docs/api-key.md)

---

### HMAC Request Signing

Every request is signed with `HMAC-SHA256` over `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH`. Replayed requests (duplicate nonce within the timestamp window) are rejected.

Required headers: `X-SecureApi-Signature`, `X-SecureApi-Timestamp`, `X-SecureApi-Nonce`.

The shared secret is stored **encrypted at rest** (AES-256-CBC via Laravel's `encrypted` cast) and can be retrieved at any time for signing.

```php
$credential = SecureApi::createHmacCredential($appId, ['name' => 'webhook-producer']);
// $credential->plaintextKey  — the shared secret for HMAC signing

// Rotate when the secret needs to change
$new = SecureApi::rotateHmacCredential($credentialId);
// $new->plaintextKey — new shared secret
```

Full details: [docs/hmac.md](https://github.com/samireltabal/secureapi/blob/main/docs/hmac.md)

---

### JWT (RS256 / HS256)

Validates Bearer JWTs. Supports externally-issued tokens (e.g. from an IdP) and internally-issued tokens via `SecureApi::issueToken()`. `alg:none` is unconditionally rejected.

```env
SECUREAPI_JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..."
SECUREAPI_JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
SECUREAPI_JWT_ISSUER=https://auth.example.com
```

Generate a fresh RS256 key pair with:

```bash
php artisan secureapi:jwt:keys
```

**Create a JWT credential and issue a token:**

```php
$credential = SecureApi::createJwtCredential($appId, ['name' => 'internal-service']);

// Issue a signed JWT (RS256 by default, uses the app's private key from config)
$token = SecureApi::issueToken($appId, ['credential_id' => $credential->id]);
// $token — signed JWT string; send as  Authorization: Bearer <token>
```

Full details: [docs/jwt.md](https://github.com/samireltabal/secureapi/blob/main/docs/jwt.md)

---

### OAuth2 Client Credentials

Built-in `POST /secureapi/oauth/token` endpoint; standard `client_credentials` grant. The client secret is stored as a SHA-256 hash; plaintext is shown once on creation.

```php
$credential = SecureApi::createOauthClientCredential($appId, ['name' => 'partner-service']);
// $credential->credential->id  — client_id
// $credential->plaintextKey    — client_secret (shown once)
```

```
POST /secureapi/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<credential->id>
&client_secret=<plaintextKey>
```

The endpoint returns a `Bearer` JWT. Protect downstream routes with:

```php
Route::middleware('secureapi:jwt')->group(fn () => ...);
```

Full details: [docs/oauth2.md](https://github.com/samireltabal/secureapi/blob/main/docs/oauth2.md)

---

### mTLS (mutual TLS)

Opt-in, fail-loud. Your TLS-terminating proxy (nginx, Envoy) verifies the client certificate and forwards the result in headers. SecureApi validates the forwarded certificate fingerprint against a stored SHA-256 hash.

```env
SECUREAPI_MTLS_ENABLED=true
SECUREAPI_MTLS_TRUSTED_PROXIES=10.0.0.1,172.16.0.0/12
```

Register a client certificate:

```bash
php artisan secureapi:mtls:register my-app-name /path/to/client.crt
```

Full details: [docs/mtls.md](https://github.com/samireltabal/secureapi/blob/main/docs/mtls.md)

---

## Middleware Reference

All aliases are registered automatically by the service provider — no manual registration needed.

| Alias | Parameters | Description |
|-------|-----------|-------------|
| `secureapi` | `mechanism,...` | Authenticate against one or more mechanisms |
| `secureapi.scopes` | `scope,...` | Require all listed scopes on the resolved credential |
| `secureapi.scope` | `scope,...` | Alias for `secureapi.scopes` |
| `secureapi.allow_ips` | — | Enforce the application's IP allowlist |
| `secureapi.throttle` | — | Enforce per-application / per-credential rate limits |
| `secureapi.audit` | — | Write an audit log entry for every request |

Example — full middleware stack for a high-security endpoint:

```php
Route::middleware([
    'secureapi:api_key',
    'secureapi.allow_ips',
    'secureapi.throttle',
    'secureapi.scopes:payments:write',
    'secureapi.audit',
])->post('/payments', PaymentController::class);
```

---

## Artisan Commands

| Command | Description |
|---------|-------------|
| `secureapi:app:create {name}` | Create an application |
| `secureapi:app:list` | List all applications |
| `secureapi:app:revoke {id}` | Revoke an application and all its credentials |
| `secureapi:app:settings {id}` | View or set application settings |
| `secureapi:credential:create {application}` | Issue a new credential |
| `secureapi:credential:revoke {id}` | Revoke a credential |
| `secureapi:credential:rotate {id}` | Rotate an API key or HMAC credential |
| `secureapi:jwt:keys` | Generate an RS256 key pair |
| `secureapi:mtls:register {app} {cert}` | Register a client certificate for mTLS |

---

## Credential Rotation

API key and HMAC credentials can be rotated without downtime. The new credential is issued first; the old one is revoked atomically inside a database transaction.

```php
// API key
$new = SecureApi::rotateApiKeyCredential($credentialId);

// HMAC
$new = SecureApi::rotateHmacCredential($credentialId);

// Both return an IssuedCredential DTO:
// $new->plaintextKey   — new secret (shown once)
// $new->credential     — new Credential model
```

Via Artisan:

```bash
php artisan secureapi:credential:rotate <credential-id>
```

---

## Configuration Reference

```php
// config/secureapi.php (published via vendor:publish --tag="secureapi-config")

'table_prefix' => env('SECUREAPI_TABLE_PREFIX', 'secure_api_'),

'oauth' => [
    'enabled'               => true,
    'path_prefix'           => 'secureapi/oauth',
    'token_ttl'             => 3600,
    'rate_limit_per_minute' => 10,
],

'mtls' => [
    'enabled'         => env('SECUREAPI_MTLS_ENABLED', false),
    'trusted_proxies' => [],          // required when enabled
    'cert_header'     => 'ssl-client-cert',
    'verify_header'   => 'ssl-client-verify',
],

'jwt' => [
    'algorithm'   => 'RS256',         // 'RS256' or 'HS256'
    'public_key'  => env('SECUREAPI_JWT_PUBLIC_KEY'),
    'private_key' => env('SECUREAPI_JWT_PRIVATE_KEY'),
    'key_id'      => env('SECUREAPI_JWT_KEY_ID'),
    'issuer'      => env('SECUREAPI_JWT_ISSUER', env('APP_URL')),
    'audience'    => env('SECUREAPI_JWT_AUDIENCE'),
    'ttl'         => 3600,
],

'audit' => [
    'retention_days' => 90,           // null = keep forever; pruned by model:prune
],

'rate_limit' => [
    'default_per_minute' => null,     // null = unlimited
],

'hmac' => [
    'timestamp_window' => 300,        // seconds; requests outside ±window are rejected
],

'replay' => [
    'cache_store' => null,            // null = app default; use 'redis' for multi-node
],
```

---

## Scopes, Rate Limiting & Audit

Full reference: [docs/scopes-rate-limiting-audit.md](https://github.com/samireltabal/secureapi/blob/main/docs/scopes-rate-limiting-audit.md)

---

## Security Model

- **API key secrets** are stored as SHA-256 hashes. Plaintext is shown once on creation and never stored.
- **HMAC secrets** are stored encrypted at rest (AES-256-CBC via Laravel's `encrypted` cast) so they can be retrieved for signing operations.
- **OAuth client secrets** are stored as SHA-256 hashes. Plaintext is shown once on creation and never stored.
- **JWT** credentials carry no secret; the server signs tokens with the RSA private key from config.
- HMAC nonces are tracked in the Laravel cache for the replay window. Use a shared cache (Redis) in multi-node deployments.
- mTLS is **fail-loud by design**: if `secureapi.mtls.enabled` is `true` but `trusted_proxies` is empty, the middleware throws `MtlsNotEnabled` (HTTP 500) rather than silently returning 401. This surfaces proxy misconfiguration immediately.
- JWT `alg:none` tokens are unconditionally rejected.
- IP allow-listing uses `Symfony\Component\HttpFoundation\IpUtils` (supports IPv4, IPv6, and CIDR).

---

## Testing

```bash
composer test          # Pest suite (164 tests)
composer analyse       # PHPStan level 8
composer format        # Laravel Pint
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](https://github.com/samireltabal/secureapi/security/policy) to report security vulnerabilities responsibly.

## Credits

- [Samir M. Eltabal](https://github.com/Samireltabal)
- [All Contributors](https://github.com/samireltabal/secureapi/contributors)

## License

The MIT License (MIT). Please see [LICENSE.md](LICENSE.md) for more information.
