# JWT Authentication

SecureApi validates externally-issued JWTs. It supports RS256 (asymmetric, recommended) and HS256 (symmetric). `alg:none` is unconditionally rejected.

## Guard setup

```php
// config/auth.php
'guards' => [
    'jwt-api' => [
        'driver'     => 'secureapi',
        'mechanisms' => ['jwt'],
    ],
],
```

## Configuration

```php
// config/secureapi.php
'jwt' => [
    'algorithm'  => 'RS256',   // or 'HS256'
    'public_key' => env('SECUREAPI_JWT_PUBLIC_KEY'),
    'private_key'=> env('SECUREAPI_JWT_PRIVATE_KEY'),   // only needed to issue tokens
    'key_id'     => env('SECUREAPI_JWT_KEY_ID'),
    'issuer'     => env('SECUREAPI_JWT_ISSUER', env('APP_URL')),
    'audience'   => env('SECUREAPI_JWT_AUDIENCE'),
    'ttl'        => 3600,
],
```

### RS256 (recommended)

Generate a key pair:

```bash
php artisan secureapi:jwt:generate-keys
```

This prints `SECUREAPI_JWT_PUBLIC_KEY` and `SECUREAPI_JWT_PRIVATE_KEY` values ready to paste into `.env`.

`.env`:

```env
SECUREAPI_JWT_ALGORITHM=RS256
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

- `sub` claim — credential ID (used to look up the credential in the database)
- `iss` claim — must match `secureapi.jwt.issuer`
- `aud` claim — must match `secureapi.jwt.audience` (if configured)
- valid `exp` (not expired)

## Making requests

```
GET /api/resource HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Accept: application/json
```

## Issuing tokens (internal use)

When SecureApi issues JWT credentials (e.g., for internal service accounts), the private key signs them. External IdPs issue tokens independently and SecureApi only validates them.

```php
$credential = SecureApi::createJwtCredential($appId, [
    'name'   => 'internal-worker',
    'scopes' => ['jobs:process'],
]);
```

## Security notes

- `alg:none` is blocked unconditionally — even if a modified JWT header requests it.
- Rotate RS256 keys by generating a new pair, updating `SECUREAPI_JWT_PUBLIC_KEY`, and re-issuing tokens. Old tokens become invalid immediately.
- For HS256, treat the secret as a password — long, random, and never logged.
