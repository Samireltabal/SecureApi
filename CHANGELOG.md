# Changelog

All notable changes to `SecureApi` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-11

### Added

- **API Key authentication** — Bearer token (`sk_<public>_<secret>`) with bcrypt-hashed secret storage.
- **HMAC request signing** — `HMAC-SHA256` over method + path + timestamp + nonce + body hash; replay protection via nonce cache.
- **JWT authentication** — RS256 (default) and HS256; `alg:none` unconditionally rejected.
- **OAuth2 client-credentials** — built-in `POST /secureapi/oauth/token` endpoint with per-application rate limiting.
- **mTLS authentication** — opt-in, fail-loud; proxy-forwarded header model with SHA-256 certificate fingerprint matching and trusted-proxy gate via `IpUtils`.
- **Scopes** — per-credential scope list; check via `SecureApi::tokenCan($scope)`.
- **IP allow-listing** — per-application `allowed_ips` enforced by `AllowedIpsMiddleware` (IPv4, IPv6, CIDR).
- **Rate limiting** — per-application and per-credential limits via `RateLimitMiddleware`.
- **Audit logging** — every authentication event is written to `secure_api_audit_logs`; retention via `model:prune`.
- **Artisan commands** — `secureapi:app:create`, `secureapi:app:list`, `secureapi:app:revoke`, `secureapi:key:issue`, `secureapi:key:revoke`, `secureapi:jwt:generate-keys`, `secureapi:mtls:register`.
- **SecureApiGuard** — `secureapi` driver for `config/auth.php`; `mechanisms` array tried in order.
- **SecureApi facade** — fluent API for creating applications and credentials.
- **PHPStan level 8** — full type coverage across all source files.
- **168-test Pest suite** — unit, integration, security hardening, and arch tests.

[Unreleased]: https://github.com/samireltabal/secureapi/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/samireltabal/secureapi/releases/tag/v1.0.0
