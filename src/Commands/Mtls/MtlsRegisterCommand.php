<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\Mtls;

use Illuminate\Console\Command;
use SamirEltabal\SecureApi\Models\Credential;
use SamirEltabal\SecureApi\SecureApi;
use SamirEltabal\SecureApi\Support\CertificateFingerprint;

class MtlsRegisterCommand extends Command
{
    protected $signature = 'secureapi:mtls:register
                            {app : Application ID}
                            {cert : Path to the PEM certificate file}
                            {--name= : Human-readable label for this certificate credential}
                            {--scopes=* : Allowed scopes (repeatable)}';

    protected $description = 'Register a client certificate for mTLS authentication';

    public function handle(SecureApi $secureApi): int
    {
        if (! (bool) config('secureapi.mtls.enabled', false)) {
            $this->error('mTLS is disabled. Set secureapi.mtls.enabled=true before registering certificates.');

            return self::FAILURE;
        }

        $applicationId = (string) $this->argument('app');
        $application = $secureApi->findApplication($applicationId);

        if ($application === null) {
            $this->error("Application [{$applicationId}] not found.");

            return self::FAILURE;
        }

        $certPath = (string) $this->argument('cert');

        if (! file_exists($certPath)) {
            $this->error("Certificate file not found: {$certPath}");

            return self::FAILURE;
        }

        $pem = file_get_contents($certPath);

        if ($pem === false) {
            $this->error("Could not read certificate file: {$certPath}");

            return self::FAILURE;
        }

        $fingerprint = CertificateFingerprint::compute($pem);

        if ($fingerprint === null) {
            $this->error('The file does not contain a valid PEM-encoded X.509 certificate.');

            return self::FAILURE;
        }

        $credential = Credential::create([
            'application_id' => $application->id,
            'type' => 'mtls_cert',
            'name' => $this->option('name'),
            'certificate_fingerprint' => $fingerprint,
            'scopes' => ! empty($this->option('scopes')) ? $this->option('scopes') : null,
            'is_active' => true,
        ]);

        $this->info('mTLS certificate registered successfully.');
        $this->newLine();
        $this->line('<comment>Credential ID:</comment>  '.$credential->id);
        $this->line('<comment>Fingerprint (SHA-256):</comment>  '.$fingerprint);
        $this->newLine();

        return self::SUCCESS;
    }
}
