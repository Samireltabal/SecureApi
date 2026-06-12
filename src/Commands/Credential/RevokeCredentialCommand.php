<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\Credential;

use Illuminate\Console\Command;
use SamirEltabal\SecureApi\SecureApi;

class RevokeCredentialCommand extends Command
{
    protected $signature = 'secureapi:credential:revoke
                            {id : Credential ID to revoke}';

    protected $description = 'Revoke a SecureApi credential immediately';

    public function handle(SecureApi $secureApi): int
    {
        $id = (string) $this->argument('id');
        $revoked = $secureApi->revokeCredential($id);

        if (! $revoked) {
            $this->error("Credential [{$id}] not found.");

            return self::FAILURE;
        }

        $this->info("Credential [{$id}] has been revoked.");

        return self::SUCCESS;
    }
}
