<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Models;

use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use SamirEltabal\SecureApi\Database\Factories\ApplicationFactory;

/**
 * @property string $id
 * @property string $name
 * @property string|null $description
 * @property array<string>|null $allowed_ips
 * @property int|null $rate_limit_per_minute
 * @property bool $is_active
 * @property Carbon|null $revoked_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class Application extends Model implements AuthenticatableContract
{
    use Authenticatable;

    /** @use HasFactory<ApplicationFactory> */
    use HasFactory;

    public $incrementing = false;

    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'name',
        'description',
        'allowed_ips',
        'rate_limit_per_minute',
        'is_active',
        'revoked_at',
    ];

    protected $casts = [
        'allowed_ips' => 'array',
        'is_active' => 'boolean',
        'revoked_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('secureapi.table_prefix', 'secure_api_').'applications';
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

    /** @return HasMany<ApplicationSetting, $this> */
    public function settings(): HasMany
    {
        return $this->hasMany(ApplicationSetting::class, 'application_id');
    }

    /** @return HasMany<Credential, $this> */
    public function credentials(): HasMany
    {
        return $this->hasMany(Credential::class, 'application_id');
    }

    /** @return HasMany<AuditLog, $this> */
    public function auditLogs(): HasMany
    {
        return $this->hasMany(AuditLog::class, 'application_id');
    }

    public function getSetting(string $key, mixed $default = null): mixed
    {
        $setting = $this->settings()->where('key', $key)->first();

        return $setting !== null ? $setting->value : $default;
    }

    public function setSetting(string $key, mixed $value): void
    {
        $this->settings()->updateOrCreate(
            ['key' => $key],
            ['value' => $value]
        );
    }

    public function forgetSetting(string $key): void
    {
        $this->settings()->where('key', $key)->delete();
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getAuthPasswordName(): string
    {
        return '';
    }
}
