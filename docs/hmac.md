# HMAC Request Signing

HMAC authentication signs every request with `HMAC-SHA256`. The signature covers the HTTP method, path, timestamp, nonce, and a hash of the request body — preventing both tampering and replay attacks.

## Route protection

```php
Route::middleware('secureapi:hmac')->group(function () {
    Route::post('/webhooks', WebhookController::class);
});
```

## Creating credentials

```php
$issued = SecureApi::createHmacCredential($appId, [
    'name'   => 'webhook-producer',
    'scopes' => ['webhooks:send'],
]);

$sharedSecret = $issued->plaintextKey; // AES-256 encrypted at rest; retrievable any time
```

## Rotating credentials

```php
$new = SecureApi::rotateHmacCredential($credentialId);
echo $new->plaintextKey; // new shared secret
```

Via Artisan:

```bash
php artisan secureapi:credential:rotate <credential-id>
```

## Required headers

All four headers are required:

```
X-SecureApi-Key-Id:    <credential-id>
X-SecureApi-Signature: <lowercase-hex-hmac-sha256>
X-SecureApi-Timestamp: <unix-timestamp>
X-SecureApi-Nonce:     <any-unique-string>
```

The credential is looked up by `X-SecureApi-Key-Id`. No `Authorization` header is used.

## Signing algorithm

```
string_to_sign = METHOD + "\n"
               + PATH + "\n"
               + UNIX_TIMESTAMP + "\n"
               + NONCE + "\n"
               + SHA256_HEX(raw_body)   // hash of empty string when no body

signature = HMAC-SHA256(string_to_sign, shared_secret)
            encoded as lowercase hex
```

Example (PHP):

```php
$method    = 'POST';
$path      = '/api/orders';
$timestamp = (string) time();
$nonce     = bin2hex(random_bytes(16));
$bodyHash  = hash('sha256', $rawBody);

$stringToSign = implode("\n", [$method, $path, $timestamp, $nonce, $bodyHash]);
$signature    = hash_hmac('sha256', $stringToSign, $sharedSecret);
```

## Replay window

Requests with a timestamp outside `±timestamp_window` seconds are rejected. The default is 300 seconds (5 minutes).

```php
// config/secureapi.php
'hmac' => [
    'timestamp_window' => 300,
],
```

Each nonce is tracked in the Laravel cache for the duration of the window. In multi-node deployments, use a shared cache store:

```php
'replay' => [
    'cache_store' => 'redis',
],
```

## Security notes

- The shared secret is stored **encrypted at rest** (AES-256-CBC via Laravel's `encrypted` cast). It can be retrieved at any time — e.g., to display it again in a management UI.
- Changing `timestamp_window` does not invalidate existing nonces — they expire based on their original timestamp.
- For the highest integrity, combine HMAC with TLS. HMAC protects request integrity; TLS provides confidentiality.
