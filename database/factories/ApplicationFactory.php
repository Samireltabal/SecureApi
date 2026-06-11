<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use SamirEltabal\SecureApi\Models\Application;

/**
 * @extends Factory<Application>
 */
class ApplicationFactory extends Factory
{
    protected $model = Application::class;

    public function definition(): array
    {
        return [
            'name' => $this->faker->unique()->company(),
            'description' => $this->faker->optional()->sentence(),
            'allowed_ips' => null,
            'rate_limit_per_minute' => null,
            'is_active' => true,
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

    public function withRateLimit(int $perMinute): static
    {
        return $this->state(fn (array $attributes) => [
            'rate_limit_per_minute' => $perMinute,
        ]);
    }

    /** @param array<string> $ips */
    public function withAllowedIps(array $ips): static
    {
        return $this->state(fn (array $attributes) => [
            'allowed_ips' => $ips,
        ]);
    }
}
