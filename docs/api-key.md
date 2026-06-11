# API Key Authentication

API key authentication is the simplest mechanism. Credentials are Bearer tokens in the format `sk_<26-char-public>_<64-char-secret>`.

## Guard setup

```php
// config/auth.php
'guards' => [
    'api' => [
        'driver'     => 'secureapi',
        'mechanisms' => ['api_key'],
    ],
],
```

## Creating credentials

```php
use SamirEltabal\SecureApi\Facades\SecureApi;

// Minimal
$credential = SecureApi::createApiKeyCredential($appId);

// With options
$credential = SecureApi::createApiKeyCredential($appId, [
    'name'    => 'mobile-client-v2',
    'scopes'  => ['read', 'write:orders'],
    'expires' => now()->addYear(),
]);

echo $credential->plaintextKey;  // shown once — store it now
```

## Making requests

```
GET /api/resource HTTP/1.1
Authorization: Bearer sk_A1B2C3D4E5F6G7H8I9J0K1L2M3_<64-char-secret>
Accept: application/json
```

## Revoking credentials

```bash
php artisan secureapi:key:revoke <credential-id>
```

Or programmatically:

```php
SecureApi::revokeCredential($credentialId);
```

## Security notes

- The `sk_…_…` token is bcrypt-hashed before storage. The plaintext is shown exactly once at creation.
- Expired (`expires_at` past) and revoked (`is_active = false` or `revoked_at` set) credentials are rejected.
- Combine with IP allow-listing (`allowed_ips` on the application) to reduce blast radius if a key leaks.
- Rotate keys by issuing a new credential and revoking the old one — no downtime required.
