<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\Credential;

use Illuminate\Console\Command;
use SamirEltabal\SecureApi\SecureApi;

class CreateCredentialCommand extends Command
{
    protected $signature = 'secureapi:credential:create
                            {application : Application ID}
                            {--name= : Human-readable name for this credential}
                            {--scopes=* : Allowed scopes (repeatable)}
                            {--expires= : Expiry date (e.g. 2025-12-31 or +1year)}';

    protected $description = 'Issue a new API key credential for a SecureApi application';

    public function handle(SecureApi $secureApi): int
    {
        $applicationId = (string) $this->argument('application');
        $application = $secureApi->findApplication($applicationId);

        if ($application === null) {
            $this->error("Application [{$applicationId}] not found.");

            return self::FAILURE;
        }

        $options = [];

        if ($this->option('name')) {
            $options['name'] = $this->option('name');
        }

        if (! empty($this->option('scopes'))) {
            $options['scopes'] = $this->option('scopes');
        }

        if ($this->option('expires')) {
            $options['expires_at'] = new \DateTime((string) $this->option('expires'));
        }

        $issued = $secureApi->createApiKeyCredential($applicationId, $options);

        $this->info('API key created successfully.');
        $this->newLine();
        $this->line('<comment>Credential ID:</comment> '.$issued->credential->id);
        $this->line('<comment>API Key (shown once):</comment>');
        $this->newLine();
        $this->line("  {$issued->plaintextKey}");
        $this->newLine();
        $this->warn('Store this key securely — it cannot be retrieved again.');

        return self::SUCCESS;
    }
}
