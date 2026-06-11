# HMAC Request Signing

HMAC authentication signs every request with `HMAC-SHA256`. The signature covers the HTTP method, path, timestamp, nonce, and a hash of the request body — preventing both tampering and replay attacks.

## Guard setup

```php
// config/auth.php
'guards' => [
    'api' => [
        'driver'     => 'secureapi',
        'mechanisms' => ['hmac'],
    ],
],
```

## Creating credentials

```php
$credential = SecureApi::createHmacCredential($appId, [
    'name'   => 'webhook-producer',
    'scopes' => ['webhooks:send'],
]);

$sharedSecret = $credential->secret;  // shown once
```

## Signing algorithm

```
string_to_sign = METHOD + "\n"
               + PATH + "\n"
               + UNIX_TIMESTAMP + "\n"
               + NONCE + "\n"
               + SHA256_HEX(raw_body)   // empty string hash when no body

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

## Required headers

```
X-SecureApi-Signature: <lowercase-hex-signature>
X-SecureApi-Timestamp: <unix-timestamp>
X-SecureApi-Nonce:     <any-unique-string>
```

The `Authorization` header is not used for HMAC — the credential is looked up by the nonce/signature pair.

## Replay window

Requests with a timestamp older than `±timestamp_window` seconds are rejected. The default is 300 seconds (5 minutes).

```php
// config/secureapi.php
'hmac' => [
    'timestamp_window' => 300,
],
```

Each nonce is tracked in the Laravel cache for the duration of the window. In multi-node deployments, configure a shared cache store:

```php
'replay' => [
    'cache_store' => 'redis',
],
```

## Security notes

- The shared secret is bcrypt-hashed at rest; plaintext shown once.
- Changing the `timestamp_window` does not invalidate existing nonces — they expire based on their original timestamp.
- For the highest integrity, combine HMAC with TLS. HMAC protects request integrity; TLS provides confidentiality.
