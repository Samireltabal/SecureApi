<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\AuditLog;

/**
 * @extends Factory<AuditLog>
 */
class AuditLogFactory extends Factory
{
    protected $model = AuditLog::class;

    public function definition(): array
    {
        return [
            'application_id' => Application::factory(),
            'credential_id' => null,
            'event' => $this->faker->randomElement(['authenticated', 'rejected', 'token_issued']),
            'ip_address' => $this->faker->ipv4(),
            'request_method' => $this->faker->randomElement(['GET', 'POST', 'PUT', 'DELETE']),
            'request_path' => '/'.implode('-', (array) $this->faker->words(2)),
            'metadata' => null,
            'created_at' => now(),
        ];
    }
}
