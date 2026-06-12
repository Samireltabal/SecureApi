<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $prefix = config('secureapi.table_prefix', 'secure_api_');

        Schema::create("{$prefix}application_settings", function (Blueprint $table) use ($prefix) {
            $table->ulid('id')->primary();
            $table->foreignUlid('application_id')
                ->constrained("{$prefix}applications")
                ->cascadeOnDelete();
            $table->string('key');
            $table->json('value');
            $table->timestamps();

            $table->unique(['application_id', 'key']);
        });
    }

    public function down(): void
    {
        $prefix = config('secureapi.table_prefix', 'secure_api_');

        Schema::dropIfExists("{$prefix}application_settings");
    }
};
