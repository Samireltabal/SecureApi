# API Key Authentication

API key authentication is the simplest mechanism. Credentials are Bearer tokens in the format `sk_<26-char-public>_<64-char-secret>`.

## Route protection

```php
Route::middleware('secureapi:api_key')->group(function () {
    Route::get('/resource', ResourceController::class);
});
```

Multiple mechanisms can be combined — the first one whose token format matches wins:

```php
Route::middleware('secureapi:api_key,jwt')->group(function () {
    Route::get('/resource', ResourceController::class);
});
```

## Creating credentials

```php
use SamirEltabal\SecureApi\Facades\SecureApi;

// Minimal
$issued = SecureApi::createApiKeyCredential($appId);

// With options
$issued = SecureApi::createApiKeyCredential($appId, [
    'name'    => 'mobile-client-v2',
    'scopes'  => ['read', 'write:orders'],
    'expires' => now()->addYear(),
]);

echo $issued->plaintextKey;   // Bearer token — shown once, store it now
echo $issued->credential->id; // ULID of the credential record
```

## Making requests

```
GET /api/resource HTTP/1.1
Authorization: Bearer sk_A1B2C3D4E5F6G7H8I9J0K1L2M3_<64-char-secret>
Accept: application/json
```

## Rotating credentials

Rotation issues a new credential and revokes the old one atomically. No downtime.

```php
$new = SecureApi::rotateApiKeyCredential($credentialId);
echo $new->plaintextKey; // new Bearer token
```

Via Artisan:

```bash
php artisan secureapi:credential:rotate <credential-id>
```

## Revoking credentials

```bash
php artisan secureapi:credential:revoke <credential-id>
```

Or programmatically:

```php
SecureApi::revokeCredential($credentialId);
```

## Security notes

- The secret portion of the `sk_…_…` token is stored as a **SHA-256 hash**. The plaintext is shown exactly once at creation and never stored.
- Expired (`expires_at` past) and revoked (`is_active = false` or `revoked_at` set) credentials are rejected.
- Combine with IP allow-listing (`allowed_ips` on the application) to reduce blast radius if a key leaks.
- Use `secureapi:credential:rotate` to rotate without downtime rather than issuing + manually revoking.
