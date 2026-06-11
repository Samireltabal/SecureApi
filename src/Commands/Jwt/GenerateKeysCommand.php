<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\Jwt;

use Illuminate\Console\Command;
use Illuminate\Support\Str;

final class GenerateKeysCommand extends Command
{
    protected $signature = 'secureapi:jwt:keys {--bits=2048 : RSA key size in bits}';

    protected $description = 'Generate an RSA key pair for JWT signing and output .env values';

    public function handle(): int
    {
        $bits = (int) $this->option('bits');

        $res = openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($res === false) {
            $this->error('Failed to generate RSA key pair. Ensure openssl is available.');

            return Command::FAILURE;
        }

        openssl_pkey_export($res, $privateKey);
        $details = openssl_pkey_get_details($res);

        if ($details === false) {
            $this->error('Failed to extract public key from generated key pair.');

            return Command::FAILURE;
        }

        $publicKey = (string) $details['key'];

        $inline = fn (string $pem) => '"'.str_replace(["\r\n", "\n"], '\n', trim($pem)).'"';

        $this->line('# Add to your .env file:');
        $this->newLine();
        $this->line('SECUREAPI_JWT_PRIVATE_KEY='.$inline($privateKey));
        $this->line('SECUREAPI_JWT_PUBLIC_KEY='.$inline($publicKey));
        $this->line('SECUREAPI_JWT_KEY_ID="'.Str::uuid().'"');
        $this->line('SECUREAPI_JWT_ISSUER="${APP_URL}"');
        $this->newLine();
        $this->info("{$bits}-bit RSA key pair generated.");

        return Command::SUCCESS;
    }
}
