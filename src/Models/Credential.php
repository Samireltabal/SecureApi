<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use SamirEltabal\SecureApi\Database\Factories\CredentialFactory;

/**
 * @property string $id
 * @property string $application_id
 * @property string $type
 * @property string|null $name
 * @property string|null $secret_hash
 * @property string|null $secret_encrypted
 * @property array<string, mixed>|null $metadata
 * @property array<string>|null $scopes
 * @property string|null $certificate_fingerprint
 * @property bool $is_active
 * @property Carbon|null $expires_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $revoked_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class Credential extends Model
{
    /** @use HasFactory<CredentialFactory> */
    use HasFactory;

    public $incrementing = false;

    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'application_id',
        'type',
        'name',
        'secret_hash',
        'secret_encrypted',
        'metadata',
        'scopes',
        'certificate_fingerprint',
        'is_active',
        'expires_at',
        'last_used_at',
        'revoked_at',
    ];

    protected $casts = [
        'secret_encrypted' => 'encrypted',
        'metadata' => 'array',
        'scopes' => 'array',
        'is_active' => 'boolean',
        'expires_at' => 'datetime',
        'last_used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('secureapi.table_prefix', 'secure_api_').'credentials';
    }

    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (self $model) {
            if (empty($model->id)) {
                $model->id = (string) Str::ulid();
            }
        });
    }

    /** @return BelongsTo<Application, $this> */
    public function application(): BelongsTo
    {
        return $this->belongsTo(Application::class, 'application_id');
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    public function isRevoked(): bool
    {
        return ! $this->is_active || $this->revoked_at !== null;
    }
}
