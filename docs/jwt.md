# JWT Authentication

SecureApi validates Bearer JWTs and can also issue them internally. Supports RS256 (asymmetric, recommended) and HS256 (symmetric). `alg:none` is unconditionally rejected.

## Route protection

```php
Route::middleware('secureapi:jwt')->group(function () {
    Route::get('/resource', ResourceController::class);
});
```

## Configuration

```php
// config/secureapi.php
'jwt' => [
    'algorithm'   => 'RS256',   // or 'HS256'
    'public_key'  => env('SECUREAPI_JWT_PUBLIC_KEY'),
    'private_key' => env('SECUREAPI_JWT_PRIVATE_KEY'),  // only needed to issue tokens
    'key_id'      => env('SECUREAPI_JWT_KEY_ID'),
    'issuer'      => env('SECUREAPI_JWT_ISSUER', env('APP_URL')),
    'audience'    => env('SECUREAPI_JWT_AUDIENCE'),
    'ttl'         => 3600,
],
```

### RS256 (recommended)

Generate a key pair:

```bash
php artisan secureapi:jwt:keys
```

This prints `SECUREAPI_JWT_PUBLIC_KEY` and `SECUREAPI_JWT_PRIVATE_KEY` values ready to paste into `.env`.

```env
SECUREAPI_JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
SECUREAPI_JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
SECUREAPI_JWT_ISSUER=https://auth.example.com
SECUREAPI_JWT_AUDIENCE=https://api.example.com
```

### HS256

Use only when you cannot manage key pairs (e.g., a constrained IoT environment). The same secret must be shared with the token issuer.

```env
SECUREAPI_JWT_ALGORITHM=HS256
SECUREAPI_JWT_PRIVATE_KEY=your-long-random-hs256-secret
```

## Token requirements

Incoming JWTs must have:

- `sub` — credential ID (used to look up the credential in the database)
- `iss` — must match `secureapi.jwt.issuer`
- `aud` — must match `secureapi.jwt.audience` (if configured)
- `exp` — must not be expired

## Making requests

```
GET /api/resource HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Accept: application/json
```

## Issuing tokens internally

Create a JWT credential and issue a signed token (uses the app's private key from config):

```php
$credential = SecureApi::createJwtCredential($appId, [
    'name'   => 'internal-worker',
    'scopes' => ['jobs:process'],
]);

$token = SecureApi::issueToken($appId, [
    'credential_id' => $credential->id,
]);
// Send as: Authorization: Bearer <token>
```

Tokens can be re-issued at any time — useful for short-lived service-account tokens.

## Validating externally-issued tokens

For external IdPs (Auth0, Keycloak, Cognito, etc.), set `public_key` to the IdP's public key and `issuer` / `audience` to match the IdP's token claims. SecureApi validates the signature and claims; no JWT credential is required for external-only setups.

## Security notes

- `alg:none` is blocked unconditionally — even if a modified JWT header requests it.
- Rotate RS256 keys by generating a new pair, updating `SECUREAPI_JWT_PUBLIC_KEY`, and re-issuing tokens. Old tokens become invalid immediately.
- For HS256, treat the key as a password — long, random, and never logged or committed.
