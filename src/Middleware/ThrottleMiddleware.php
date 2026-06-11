<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use SamirEltabal\SecureApi\Support\SecureApiContext;
use Symfony\Component\HttpFoundation\Response;

final class ThrottleMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $credential = SecureApiContext::credential($request);

        if ($credential === null) {
            return $next($request);
        }

        $maxAttempts = $credential->application->rate_limit_per_minute
            ?? config('secureapi.rate_limit.default_per_minute');

        if ($maxAttempts === null) {
            return $next($request);
        }

        $key = "secureapi:cred:{$credential->id}";
        $max = (int) $maxAttempts;

        if (RateLimiter::tooManyAttempts($key, $max)) {
            abort(429, 'Rate limit exceeded.');
        }

        RateLimiter::hit($key, 60);

        return $next($request);
    }
}
