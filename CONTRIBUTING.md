# Contributing

Thank you for considering contributing to SecureApi!

## Setup

```bash
git clone https://github.com/samireltabal/secureapi.git
cd secureapi
composer install
```

## Running the test suite

```bash
composer test          # Pest suite
composer analyse       # PHPStan level 8
composer format        # Laravel Pint
```

All pull requests must pass the full test suite and PHPStan level 8 analysis. Please add tests for any new behaviour.

## Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. Write tests first (red → green → refactor).
3. Ensure `composer test` and `composer analyse` both pass with no errors.
4. Run `composer format` before committing.
5. Open a pull request with a clear description of the change and its motivation.

## Security Vulnerabilities

Please do **not** open a public issue for security vulnerabilities. Review the [security policy](https://github.com/samireltabal/secureapi/security/policy) and report privately.
