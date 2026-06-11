<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use SamirEltabal\SecureApi\Database\Factories\AuditLogFactory;

/**
 * @property string $id
 * @property string $application_id
 * @property string|null $credential_id
 * @property string $event
 * @property string|null $ip_address
 * @property string|null $request_method
 * @property string|null $request_path
 * @property array<string, mixed>|null $metadata
 * @property Carbon $created_at
 */
class AuditLog extends Model
{
    /** @use HasFactory<AuditLogFactory> */
    use HasFactory;

    use MassPrunable;

    public $incrementing = false;

    public $timestamps = false;

    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'application_id',
        'credential_id',
        'event',
        'ip_address',
        'request_method',
        'request_path',
        'metadata',
        'created_at',
    ];

    protected $casts = [
        'metadata' => 'array',
        'created_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('secureapi.table_prefix', 'secure_api_').'audit_logs';
    }

    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (self $model) {
            if (empty($model->id)) {
                $model->id = (string) Str::ulid();
            }
            if (empty($model->created_at)) {
                $model->created_at = now();
            }
        });
    }

    /** @return Builder<AuditLog> */
    public function prunable(): Builder
    {
        $days = config('secureapi.audit.retention_days');

        if ($days === null) {
            /** @var Builder<AuditLog> */
            return self::query()->whereRaw('1 = 0');
        }

        /** @var Builder<AuditLog> */
        return self::query()->where('created_at', '<', now()->subDays($days));
    }

    /** @return BelongsTo<Application, $this> */
    public function application(): BelongsTo
    {
        return $this->belongsTo(Application::class, 'application_id');
    }

    /** @return BelongsTo<Credential, $this> */
    public function credential(): BelongsTo
    {
        return $this->belongsTo(Credential::class, 'credential_id');
    }
}
