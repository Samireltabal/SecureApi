<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\App;

use Illuminate\Console\Command;
use SamirEltabal\SecureApi\SecureApi;

class RevokeAppCommand extends Command
{
    protected $signature = 'secureapi:app:revoke
                            {id : The application ID}
                            {--force : Skip confirmation prompt}';

    protected $description = 'Revoke a SecureApi application and all its credentials';

    public function handle(SecureApi $secureApi): int
    {
        $id = (string) $this->argument('id');
        $application = $secureApi->findApplication($id);

        if ($application === null) {
            $this->error("Application [{$id}] not found.");

            return self::FAILURE;
        }

        if (! $this->option('force') && ! $this->confirm("Revoke application [{$application->name}]? This will invalidate all its credentials.")) {
            $this->info('Revocation cancelled.');

            return self::SUCCESS;
        }

        $secureApi->revokeApplication($id);

        $this->info("Application [{$application->name}] has been revoked.");

        return self::SUCCESS;
    }
}
