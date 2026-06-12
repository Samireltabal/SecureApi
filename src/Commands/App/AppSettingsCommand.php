<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Commands\App;

use Illuminate\Console\Command;
use SamirEltabal\SecureApi\Models\ApplicationSetting;
use SamirEltabal\SecureApi\SecureApi;

class AppSettingsCommand extends Command
{
    protected $signature = 'secureapi:app:settings
                            {id : The application ID}
                            {--set=* : Set a setting as key=value (can be repeated)}
                            {--forget=* : Remove a setting by key (can be repeated)}
                            {--list : List all settings for this application}';

    protected $description = 'Manage settings for a SecureApi application';

    public function handle(SecureApi $secureApi): int
    {
        $id = (string) $this->argument('id');
        $application = $secureApi->findApplication($id);

        if ($application === null) {
            $this->error("Application [{$id}] not found.");

            return self::FAILURE;
        }

        foreach ((array) $this->option('forget') as $key) {
            if (! is_string($key)) {
                continue;
            }
            $application->forgetSetting($key);
            $this->line("Removed setting: {$key}");
        }

        foreach ((array) $this->option('set') as $pair) {
            if (! is_string($pair)) {
                continue;
            }
            [$key, $value] = explode('=', $pair, 2);
            $application->setSetting(trim($key), trim($value));
            $this->line("Set {$key} = {$value}");
        }

        if ($this->option('list') || (empty($this->option('set')) && empty($this->option('forget')))) {
            $settings = $application->settings()->get();

            if ($settings->isEmpty()) {
                $this->info("No settings configured for [{$application->name}].");

                return self::SUCCESS;
            }

            $this->table(
                ['Key', 'Value'],
                $settings->map(fn (ApplicationSetting $s) => [
                    $s->key,
                    json_encode($s->value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
                ])->toArray()
            );
        }

        return self::SUCCESS;
    }
}
