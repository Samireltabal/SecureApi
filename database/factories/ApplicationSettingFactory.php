<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use SamirEltabal\SecureApi\Models\Application;
use SamirEltabal\SecureApi\Models\ApplicationSetting;

/**
 * @extends Factory<ApplicationSetting>
 */
class ApplicationSettingFactory extends Factory
{
    protected $model = ApplicationSetting::class;

    public function definition(): array
    {
        return [
            'application_id' => Application::factory(),
            'key' => $this->faker->unique()->word(),
            'value' => $this->faker->sentence(),
        ];
    }
}
