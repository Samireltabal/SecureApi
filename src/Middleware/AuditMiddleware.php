<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Middleware;

use Closure;
use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Models\AuditLog;
use SamirEltabal\SecureApi\Support\SecureApiContext;
use Symfony\Component\HttpFoundation\Response;

final class AuditMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $credential = SecureApiContext::credential($request);

        if ($credential !== null) {
            AuditLog::create([
                'application_id' => $credential->application_id,
                'credential_id' => $credential->id,
                'event' => $this->eventFromStatus($response->getStatusCode()),
                'ip_address' => $request->ip(),
                'request_method' => $request->method(),
                'request_path' => $request->getPathInfo(),
            ]);
        }

        return $response;
    }

    private function eventFromStatus(int $status): string
    {
        return match (true) {
            $status === 429 => 'auth.rate_limited',
            $status >= 200 && $status < 300 => 'auth.success',
            default => 'auth.forbidden',
        };
    }
}
