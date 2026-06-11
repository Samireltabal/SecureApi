# OAuth2 Client Credentials

SecureApi ships a built-in `client_credentials` grant endpoint. No separate OAuth2 server is required.

## Guard setup

```php
// config/auth.php
'guards' => [
    'api' => [
        'driver'     => 'secureapi',
        'mechanisms' => ['oauth2'],
    ],
],
```

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
$credential = SecureApi::createOauthClientCredential($appId, [
    'name'   => 'partner-billing-service',
    'scopes' => ['billing:read', 'billing:write'],
]);

// $credential->id           — client_id
// $credential->plaintextKey — client_secret (shown once)
```

## Token request

```
POST /secureapi/oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<credential_id>
&client_secret=<plaintextKey>
```

Response:

```json
{
    "access_token": "sk_..._...",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

## Using the token

```
GET /api/resource HTTP/1.1
Authorization: Bearer <access_token>
Accept: application/json
```

## Security notes

- Client secrets are bcrypt-hashed at rest; plaintext shown once.
- The token endpoint is rate-limited independently (default: 10 requests/minute per client). Configure via `oauth.rate_limit_per_minute`.
- Issued access tokens are standard SecureApi API keys — they are subject to the same expiry, revocation, and IP allow-list checks as manually created keys.
- For the highest security, combine with IP allow-listing on the application so tokens are only usable from known source IPs.
