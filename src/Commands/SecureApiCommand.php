<?php

namespace SamirEltabal\SecureApi\Commands;

use Illuminate\Console\Command;

class SecureApiCommand extends Command
{
    public $signature = 'secureapi';

    public $description = 'My command';

    public function handle(): int
    {
        $this->comment('All done');

        return self::SUCCESS;
    }
}
