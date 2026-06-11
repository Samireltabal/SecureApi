<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Support;

use Illuminate\Support\Facades\Cache;

final class NonceStore
{
    /**
     * Atomically record a nonce. Returns true if the nonce is fresh (first use),
     * false if it was already consumed (replay detected).
     */
    public function consume(string $keyId, string $nonce, int $ttl): bool
    {
        $cacheStore = config('secureapi.replay.cache_store');

        return Cache::store($cacheStore)->add(
            "secureapi:nonce:{$keyId}:{$nonce}",
            true,
            $ttl,
        );
    }
}
