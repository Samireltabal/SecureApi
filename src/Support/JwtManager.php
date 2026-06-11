<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Support;

use DateTimeImmutable;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use SamirEltabal\SecureApi\Exceptions\AuthenticationFailedException;
use Throwable;

final class JwtManager
{
    private readonly Configuration $jwtConfig;

    private readonly string $algorithm;

    /** @param array<string,mixed> $config */
    public function __construct(private readonly array $config)
    {
        $this->algorithm = (string) ($config['algorithm'] ?? 'RS256');
        $this->jwtConfig = $this->buildConfiguration();
    }

    private function buildConfiguration(): Configuration
    {
        if ($this->algorithm === 'HS256') {
            $secret = (string) ($this->config['private_key'] ?? '');

            if ($secret === '') {
                throw new \RuntimeException(
                    'JWT HS256 secret key is empty. Set SECUREAPI_JWT_PRIVATE_KEY in your .env file.'
                );
            }

            return Configuration::forSymmetricSigner(
                new HmacSha256,
                InMemory::plainText($secret),
            );
        }

        $privateKey = (string) ($this->config['private_key'] ?? '');
        $publicKey = (string) ($this->config['public_key'] ?? '');

        if ($publicKey === '') {
            throw new \RuntimeException(
                'JWT RS256 public key is empty. Set SECUREAPI_JWT_PUBLIC_KEY in your .env file.'
            );
        }

        $signingKey = $privateKey !== '' ? $privateKey : $publicKey;

        return Configuration::forAsymmetricSigner(
            new RsaSha256,
            InMemory::plainText($signingKey),
            InMemory::plainText($publicKey),
        );
    }

    /**
     * Issue a signed JWT for the given credential.
     *
     * @param  array<string>  $scopes
     * @param  array<string,mixed>  $extraClaims
     */
    public function issue(string $credentialId, array $scopes = [], ?int $ttl = null, array $extraClaims = []): string
    {
        $now = new DateTimeImmutable;
        $seconds = $ttl ?? (int) ($this->config['ttl'] ?? 3600);
        $jti = Str::uuid()->toString();

        $builder = $this->jwtConfig->builder()
            ->identifiedBy($jti)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify("+{$seconds} seconds"))
            ->relatedTo($credentialId !== '' ? $credentialId : throw new \InvalidArgumentException('credentialId must not be empty'));

        $issuer = (string) ($this->config['issuer'] ?? '');
        if ($issuer !== '') {
            $builder = $builder->issuedBy($issuer);
        }

        $audience = (string) ($this->config['audience'] ?? '');
        if ($audience !== '') {
            $builder = $builder->permittedFor($audience);
        }

        if ($scopes !== []) {
            $builder = $builder->withClaim('scopes', $scopes);
        }

        foreach ($extraClaims as $name => $value) {
            $claimName = (string) $name;
            if ($claimName !== '') {
                $builder = $builder->withClaim($claimName, $value);
            }
        }

        return $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey())->toString();
    }

    /**
     * Parse a JWT string, rejecting alg=none tokens before signature verification.
     *
     * @throws AuthenticationFailedException
     */
    public function parse(string $tokenString): UnencryptedToken
    {
        $this->guardAgainstAlgNone($tokenString);

        try {
            $token = $this->jwtConfig->parser()->parse($tokenString !== '' ? $tokenString : throw AuthenticationFailedException::invalidToken());
        } catch (Throwable) {
            throw AuthenticationFailedException::invalidToken();
        }

        if (! $token instanceof UnencryptedToken) {
            throw AuthenticationFailedException::invalidToken();
        }

        return $token;
    }

    /**
     * Validate a parsed token against signature, time constraints, and configured claims.
     *
     * @throws AuthenticationFailedException
     */
    public function validate(UnencryptedToken $token): void
    {
        $clock = new SystemClock;

        $constraints = [
            new SignedWith($this->jwtConfig->signer(), $this->jwtConfig->verificationKey()),
            new StrictValidAt($clock),
        ];

        $issuer = (string) ($this->config['issuer'] ?? '');
        if ($issuer !== '') {
            $constraints[] = new IssuedBy($issuer);
        }

        $audience = (string) ($this->config['audience'] ?? '');
        if ($audience !== '') {
            $constraints[] = new PermittedFor($audience);
        }

        try {
            $this->jwtConfig->validator()->assert($token, ...$constraints);
        } catch (Throwable) {
            throw AuthenticationFailedException::invalidToken();
        }
    }

    private function guardAgainstAlgNone(string $tokenString): void
    {
        $parts = explode('.', $tokenString);

        if (count($parts) !== 3) {
            throw AuthenticationFailedException::invalidToken();
        }

        try {
            $headerJson = base64_decode(strtr($parts[0], '-_', '+/'), strict: false);
            /** @var array<string,mixed>|null $header */
            $header = json_decode((string) $headerJson, associative: true);
        } catch (Throwable) {
            throw AuthenticationFailedException::invalidToken();
        }

        $alg = (string) ($header['alg'] ?? '');

        if ($alg === '' || $alg === 'none') {
            throw AuthenticationFailedException::invalidToken('algorithm_not_allowed');
        }
    }
}
