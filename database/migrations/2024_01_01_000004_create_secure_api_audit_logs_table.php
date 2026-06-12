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

        Schema::create("{$prefix}audit_logs", function (Blueprint $table) use ($prefix) {
            $table->ulid('id')->primary();
            $table->foreignUlid('application_id')
                ->constrained("{$prefix}applications")
                ->cascadeOnDelete();
            $table->foreignUlid('credential_id')
                ->nullable()
                ->constrained("{$prefix}credentials")
                ->nullOnDelete();
            $table->string('event'); // authenticated | rejected | token_issued | revoked etc.
            $table->string('ip_address', 45)->nullable();
            $table->string('request_method', 10)->nullable();
            $table->string('request_path')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('created_at')->nullable();

            $table->index(['application_id', 'created_at']);
            $table->index(['credential_id', 'created_at']);
        });
    }

    public function down(): void
    {
        $prefix = config('secureapi.table_prefix', 'secure_api_');

        Schema::dropIfExists("{$prefix}audit_logs");
    }
};
