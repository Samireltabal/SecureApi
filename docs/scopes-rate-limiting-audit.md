# Scopes, Rate Limiting & Audit Logs

## Scopes

Scopes restrict what a credential can do. They are stored as a JSON array on the credential.

### Assigning scopes

```php
$issued = SecureApi::createApiKeyCredential($appId, [
    'scopes' => ['orders:read', 'orders:write', 'products:read'],
]);
```

### Enforcing scopes via middleware

```php
// Require all listed scopes on the resolved credential
Route::middleware(['secureapi:api_key', 'secureapi.scopes:orders:read'])->group(function () {
    Route::get('/orders', OrderController::class);
});
```

`secureapi.scope` is an alias for `secureapi.scopes` — both work.

### Checking scopes programmatically

```php
// In a controller — after successful authentication
if (! $request->attributes->get('secureapi.credential')?->hasScope('orders:write')) {
    abort(403, 'Insufficient scope');
}
```

A credential with **no scopes** has unrestricted access; scopes only restrict when explicitly set.

### Scope naming convention

Use `resource:action` format: `orders:read`, `webhooks:send`, `admin:users:write`. Scopes are case-sensitive.

---

## Rate Limiting

Rate limiting is enforced by the `secureapi.throttle` middleware using Laravel's built-in `RateLimiter`.

### Default limit (application-wide)

```php
// config/secureapi.php
'rate_limit' => [
    'default_per_minute' => 60,   // null = unlimited
],
```

### Per-application override

Set `rate_limit_per_minute` directly on the application model:

```php
$application->update(['rate_limit_per_minute' => 120]);
```

Or via Artisan:

```bash
php artisan secureapi:app:settings <app-id>
```

### Applying the middleware

```php
Route::middleware(['secureapi:api_key', 'secureapi.throttle'])->group(function () {
    Route::get('/resource', ResourceController::class);
});
```

When a client exceeds the limit, SecureApi returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 30
```

---

## Audit Logs

Every authentication failure is written to `secure_api_audit_logs`. Successes are also logged when the `secureapi.audit` middleware is on the route.

### Applying the audit middleware

```php
Route::middleware(['secureapi:api_key', 'secureapi.audit'])->group(function () {
    Route::post('/transactions', TransactionController::class);
});
```

### Schema

| Column | Type | Description |
|--------|------|-------------|
| `id` | ULID | Primary key |
| `application_id` | ULID | Authenticated application (nullable on failure) |
| `credential_id` | ULID | Authenticated credential (nullable on failure) |
| `event` | string | `auth.failed`, `auth.success`, etc. |
| `ip_address` | string | Client IP |
| `request_method` | string | HTTP method |
| `request_path` | string | Request path |
| `metadata` | JSON | Mechanism, failure reason, etc. |
| `created_at` | timestamp | Log creation time |

### Querying logs

```php
use SamirEltabal\SecureApi\Models\AuditLog;

// All failed attempts in the last hour
AuditLog::where('event', 'auth.failed')
    ->where('created_at', '>=', now()->subHour())
    ->get();

// All events for a specific application
AuditLog::where('application_id', $appId)->latest('created_at')->get();
```

### Retention / pruning

```php
// config/secureapi.php
'audit' => [
    'retention_days' => 90,   // null = keep forever
],
```

`AuditLog` uses `MassPrunable`. Schedule it in your console routes:

```php
// routes/console.php (Laravel 11+)
Schedule::command('model:prune', ['--model' => \SamirEltabal\SecureApi\Models\AuditLog::class])
    ->daily();
```

Or include it in a general prune if you have other prunable models:

```bash
php artisan model:prune
```

Logs older than `retention_days` are deleted in batches without loading them into memory.
