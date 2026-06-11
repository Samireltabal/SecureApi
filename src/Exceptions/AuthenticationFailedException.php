<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Exceptions;

use RuntimeException;
use Throwable;

final class AuthenticationFailedException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $reason = 'unknown',
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function invalidCredential(): self
    {
        return new self('Invalid API key.', 'invalid_credential');
    }

    public static function revoked(): self
    {
        return new self('Credential has been revoked.', 'revoked');
    }

    public static function expired(): self
    {
        return new self('Credential has expired.', 'expired');
    }

    public static function applicationInactive(): self
    {
        return new self('Application is inactive or revoked.', 'application_inactive');
    }

    public static function timestampOutOfWindow(): self
    {
        return new self('Request timestamp is outside the allowed window.', 'timestamp_out_of_window');
    }

    public static function replayed(): self
    {
        return new self('Nonce has already been used.', 'replayed');
    }

    public static function invalidToken(string $reason = 'invalid_token'): self
    {
        return new self('Invalid or expired bearer token.', $reason);
    }
}
