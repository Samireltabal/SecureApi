# Scopes, Rate Limiting & Audit Logs

## Scopes

Scopes restrict what a credential can do. They are stored as a JSON array on the credential.

### Assigning scopes

```php
$credential = SecureApi::createApiKeyCredential($appId, [
    'scopes' => ['orders:read', 'orders:write', 'products:read'],
]);
```

### Checking scopes

```php
// In a controller or middleware — after successful authentication
if (! SecureApi::tokenCan('orders:write')) {
    abort(403, 'Insufficient scope');
}
```

`SecureApi::tokenCan()` returns `true` if the current credential has the given scope (or has no scopes — no-scope credentials have unrestricted access).

### Scope naming convention

Use `resource:action` format: `orders:read`, `webhooks:send`, `admin:users:write`. Scopes are case-sensitive.

---

## Rate Limiting

Rate limiting is enforced by `RateLimitMiddleware` using Laravel's built-in `RateLimiter`.

### Default limit (application-wide)

```php
// config/secureapi.php
'rate_limit' => [
    'default_per_minute' => 60,   // null = unlimited
],
```

### Per-application override

```php
// Set via Artisan or programmatically
$application->rate_limit_per_minute = 120;
$application->save();
```

### Applying the middleware

```php
// routes/api.php
Route::middleware(['auth:api', 'secureapi.rate_limit'])->group(function () {
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

Every authentication event — success and failure — is written to `secure_api_audit_logs`.

### Schema

| Column | Type | Description |
|--------|------|-------------|
| `id` | ULID | Primary key |
| `application_id` | ULID | Authenticated application (nullable on failure) |
| `credential_id` | ULID | Authenticated credential (nullable on failure) |
| `event` | string | `authenticated`, `failed`, `rate_limited`, etc. |
| `ip_address` | string | Client IP |
| `request_method` | string | HTTP method |
| `request_path` | string | Request path |
| `metadata` | JSON | Mechanism, failure reason, etc. |
| `created_at` | timestamp | Log creation time |

### Querying logs

```php
use SamirEltabal\SecureApi\Models\AuditLog;

// All failed attempts in the last hour
AuditLog::where('event', 'failed')
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

Pruning uses Laravel's `MassPrunable`. Schedule it in your console kernel:

```php
// routes/console.php (Laravel 11+)
Schedule::command('model:prune', ['--model' => AuditLog::class])
    ->daily();
```

Or via the general prune command if you have other prunable models:

```bash
php artisan model:prune
```

Logs older than `retention_days` are deleted in batches without loading them into memory.
