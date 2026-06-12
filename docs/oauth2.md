# OAuth2 Client Credentials

SecureApi ships a built-in `client_credentials` grant endpoint. No separate OAuth2 server is required. The token endpoint issues a signed JWT; downstream routes protect themselves with the `jwt` mechanism.

## Configuration

```php
// config/secureapi.php
'oauth' => [
    'enabled'               => true,
    'path_prefix'           => 'secureapi/oauth',   // token URL: POST /<prefix>/token
    'token_ttl'             => 3600,                // seconds
    'rate_limit_per_minute' => 10,
],
```

## Creating OAuth2 client credentials

```php
$issued = SecureApi::createOauthClientCredential($appId, [
    'name'   => 'partner-billing-service',
    'scopes' => ['billing:read', 'billing:write'],
]);

$clientId     = $issued->credential->id;  // use as client_id
$clientSecret = $issued->plaintextKey;    // use as client_secret — shown once
```

## Token request

Credentials can be sent either in the request body or as HTTP Basic Auth (`client_id:client_secret`).

**Body parameters:**

```
POST /secureapi/oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<credential->credential->id>
&client_secret=<plaintextKey>
&scope=billing:read billing:write
```

**HTTP Basic Auth:**

```
POST /secureapi/oauth/token HTTP/1.1
Authorization: Basic base64(<client_id>:<client_secret>)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

**Response:**

```json
{
    "access_token": "eyJhbGciOiJSUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "billing:read billing:write"
}
```

The `access_token` is a signed JWT. Scopes in the response are space-separated.

## Protecting downstream routes

Routes that accept OAuth2 access tokens use the `jwt` mechanism (since the token is a JWT):

```php
Route::middleware('secureapi:jwt')->group(function () {
    Route::get('/billing/invoices', InvoiceController::class);
});
```

## Using the token

```
GET /billing/invoices HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Accept: application/json
```

## Security notes

- Client secrets are stored as **SHA-256 hashes**. Plaintext is shown once at creation and never stored.
- The token endpoint is rate-limited independently (default: 10 req/min per IP). Configure via `oauth.rate_limit_per_minute`.
- Requested `scope` values must be a subset of the credential's assigned scopes. Unknown scopes return `invalid_scope`.
- For maximum security, combine with IP allow-listing on the application so tokens are only usable from known source IPs.
- The `Cache-Control: no-store` and `Pragma: no-cache` headers are included in all token responses per RFC 6749.
