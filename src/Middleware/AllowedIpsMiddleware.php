<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Middleware;

use Closure;
use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Support\SecureApiContext;
use Symfony\Component\HttpFoundation\Response;

final class AllowedIpsMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $credential = SecureApiContext::credential($request);

        if ($credential === null) {
            return $next($request);
        }

        $application = $credential->application;
        $allowedIps = $application !== null ? $application->allowed_ips : null;

        if ($allowedIps === null) {
            return $next($request);
        }

        $clientIp = $request->ip() ?? '';

        if (! $this->ipInList($clientIp, $allowedIps)) {
            abort(403, 'IP address not in the allowed list.');
        }

        return $next($request);
    }

    /** @param string[] $allowedIps */
    private function ipInList(string $ip, array $allowedIps): bool
    {
        foreach ($allowedIps as $allowed) {
            if ($ip === $allowed) {
                return true;
            }

            if (str_contains($allowed, '/') && $this->ipInCidr($ip, $allowed)) {
                return true;
            }
        }

        return false;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        $mask = ~((1 << (32 - $bits)) - 1);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }
}
