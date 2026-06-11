<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\Credential;

use Illuminate\Console\Command;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\SecureApi;

class RotateCredentialCommand extends Command
{
    protected $signature = 'secureapi:credential:rotate
                            {id : Credential ID to rotate}';

    protected $description = 'Rotate (replace) the secret for a SecureApi API key credential';

    public function handle(SecureApi $secureApi): int
    {
        $id = $this->argument('id');
        $credential = Credential::find($id);

        if ($credential === null) {
            $this->error("Credential [{$id}] not found.");

            return self::FAILURE;
        }

        $issued = $secureApi->rotateApiKeyCredential($id);

        $this->info("Credential [{$id}] secret has been rotated.");
        $this->newLine();
        $this->line('<comment>New API Key (shown once):</comment>');
        $this->newLine();
        $this->line("  {$issued->plaintextKey}");
        $this->newLine();
        $this->warn('Store this key securely — it cannot be retrieved again.');

        return self::SUCCESS;
    }
}
