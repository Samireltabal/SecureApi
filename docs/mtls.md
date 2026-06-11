# mTLS Authentication

mTLS (mutual TLS) verifies the client by a certificate fingerprint. SecureApi uses a **proxy-forwarded header model**: your TLS-terminating proxy (nginx, Envoy, Caddy) validates the client certificate and forwards the result in HTTP headers. PHP never sees raw TLS — it trusts the proxy.

**Fail-loud design**: if `secureapi.mtls.enabled` is `true` but `trusted_proxies` is empty (or vice versa), the mechanism throws `MtlsNotEnabled` (HTTP 500) rather than silently returning 401. This surfaces infrastructure misconfiguration immediately.

## Guard setup

```php
// config/auth.php
'guards' => [
    'mtls-api' => [
        'driver'     => 'secureapi',
        'mechanisms' => ['mtls'],
    ],
],
```

## Configuration

```php
// config/secureapi.php
'mtls' => [
    'enabled'          => env('SECUREAPI_MTLS_ENABLED', false),
    'trusted_proxies'  => array_filter(
        explode(',', env('SECUREAPI_MTLS_TRUSTED_PROXIES', ''))
    ),
    'verify_header'    => 'ssl-client-verify',   // header set to SUCCESS on valid cert
    'cert_header'      => 'ssl-client-cert',     // URL-encoded PEM of the client cert
],
```

`.env`:

```env
SECUREAPI_MTLS_ENABLED=true
SECUREAPI_MTLS_TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8
```

Both `enabled=true` **and** a non-empty `trusted_proxies` list are required. Missing either causes the package to throw `MtlsNotEnabled`.

## Registering a client certificate

```bash
php artisan secureapi:mtls:register <app-name> /path/to/client.crt
```

This computes the SHA-256 fingerprint of the PEM certificate and stores it on a new `mtls_cert` credential. The command is blocked when `secureapi.mtls.enabled` is `false`.

## nginx configuration

nginx 1.13.5+ exposes `$ssl_client_escaped_cert` (URL-encoded PEM), which SecureApi reads directly.

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/ssl/server.crt;
    ssl_certificate_key /etc/ssl/server.key;
    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client   on;

    location / {
        proxy_pass http://php-fpm:9000;

        proxy_set_header ssl-client-verify  $ssl_client_verify;
        proxy_set_header ssl-client-cert    $ssl_client_escaped_cert;
        proxy_set_header X-Forwarded-For    $remote_addr;
        proxy_set_header X-Real-IP          $remote_addr;
    }
}
```

`$ssl_client_verify` is set to `SUCCESS` when the certificate is valid and the chain verifies against `ssl_client_certificate`.

## Local playground with Docker

The repo ships a Docker-based playground for local mTLS testing.

### 1. Generate CA, server cert, and client cert

```bash
bash docker/nginx-mtls/generate-certs.sh
```

This creates `docker/nginx-mtls/certs/` with:
- `ca.crt` / `ca.key` — local CA
- `server.crt` / `server.key` — nginx TLS certificate
- `client.crt` / `client.key` — client certificate (for curl/Postman)

The script also prints the client certificate SHA-256 fingerprint.

### 2. Start the nginx-mtls service

```bash
docker compose --profile mtls up -d
```

This starts an nginx container on `https://localhost:8443` that terminates mTLS and proxies to your Laravel app.

### 3. Register the client certificate

```bash
php artisan secureapi:mtls:register my-app docker/nginx-mtls/certs/client.crt
```

### 4. Test with curl

```bash
curl -k \
  --cert docker/nginx-mtls/certs/client.crt \
  --key  docker/nginx-mtls/certs/client.key \
  https://localhost:8443/mtls-protected
```

Without `--cert`, nginx returns 400 (certificate required). With `--cert` but a fingerprint mismatch, SecureApi returns 401.

## Security notes

- **Never** forward `ssl-client-verify` or `ssl-client-cert` from untrusted sources. SecureApi validates that `REMOTE_ADDR` is in `trusted_proxies` before reading the headers. Requests from non-trusted IPs get an immediate 401.
- Revoke a certificate by revoking the credential: `secureapi:key:revoke <credential-id>`. The fingerprint remains in the database for audit purposes.
- For zero-trust environments, combine mTLS with scope restrictions and per-application IP allow-listing.
- Use IPv6 CIDR ranges in `trusted_proxies` where applicable — `IpUtils::checkIp()` handles both IPv4 and IPv6.
