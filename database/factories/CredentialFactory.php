<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\Credential;

/**
 * @extends Factory<Credential>
 */
class CredentialFactory extends Factory
{
    protected $model = Credential::class;

    public function definition(): array
    {
        return [
            'application_id' => Application::factory(),
            'type' => 'api_key',
            'name' => $this->faker->optional()->words(3, true),
            'secret_hash' => null,
            'metadata' => null,
            'scopes' => null,
            'is_active' => true,
            'expires_at' => null,
            'last_used_at' => null,
            'revoked_at' => null,
        ];
    }

    public function revoked(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
            'revoked_at' => now(),
        ]);
    }

    public function expired(): static
    {
        return $this->state(fn (array $attributes) => [
            'expires_at' => now()->subMinute(),
        ]);
    }
}
