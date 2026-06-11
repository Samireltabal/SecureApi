<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\App;

use Illuminate\Console\Command;
use SamirEltabal\SecureApi\SecureApi;

class CreateAppCommand extends Command
{
    protected $signature = 'secureapi:app:create
                            {name : The application name}
                            {--description= : Optional description}
                            {--rate-limit= : Rate limit requests per minute (empty = unlimited)}';

    protected $description = 'Create a new SecureApi application';

    public function handle(SecureApi $secureApi): int
    {
        $options = array_filter([
            'description' => $this->option('description'),
            'rate_limit_per_minute' => $this->option('rate-limit') !== null
                ? (int) $this->option('rate-limit')
                : null,
        ], fn ($v) => $v !== null);

        $application = $secureApi->createApplication($this->argument('name'), $options);

        $this->info('Application created successfully.');
        $this->table(['Field', 'Value'], [
            ['ID', $application->id],
            ['Name', $application->name],
            ['Description', $application->description ?? '—'],
            ['Rate Limit', $application->rate_limit_per_minute ? "{$application->rate_limit_per_minute}/min" : 'Unlimited'],
            ['Active', $application->is_active ? 'Yes' : 'No'],
            ['Created', $application->created_at->toDateTimeString()],
        ]);

        return self::SUCCESS;
    }
}
