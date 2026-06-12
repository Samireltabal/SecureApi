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

        Schema::create("{$prefix}credentials", function (Blueprint $table) use ($prefix) {
            $table->ulid('id')->primary();
            $table->foreignUlid('application_id')
                ->constrained("{$prefix}applications")
                ->cascadeOnDelete();
            $table->string('type'); // api_key | hmac | jwt | oauth_client | mtls
            $table->string('name')->nullable();
            $table->string('secret_hash')->nullable(); // sha256 hash for api_key/oauth
            $table->text('secret_encrypted')->nullable(); // Laravel-encrypted raw secret for hmac
            $table->json('metadata')->nullable(); // mechanism-specific extra data
            $table->json('scopes')->nullable(); // allowed scopes array
            $table->string('certificate_fingerprint')->nullable()->index(); // SHA-256 hex for mtls_cert type
            $table->boolean('is_active')->default(true);
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index(['application_id', 'type']);
        });
    }

    public function down(): void
    {
        $prefix = config('secureapi.table_prefix', 'secure_api_');

        Schema::dropIfExists("{$prefix}credentials");
    }
};
