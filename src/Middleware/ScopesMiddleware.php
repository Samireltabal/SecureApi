<?php

declare(strict_types=1);

namespace SamirEltabal\SecureApi\Middleware;

use Closure;
use Illuminate\Http\Request;
use SamirEltabal\SecureApi\Support\SecureApiContext;
use Symfony\Component\HttpFoundation\Response;

final class ScopesMiddleware
{
    public function handle(Request $request, Closure $next, string ...$requiredScopes): Response
    {
        $credential = SecureApiContext::credential($request);

        if ($credential === null) {
            abort(403, 'No authenticated credential on this request.');
        }

        // Null scopes = no restriction (credential has unlimited access)
        if ($credential->scopes !== null) {
            foreach ($requiredScopes as $scope) {
                if (! in_array($scope, $credential->scopes, true)) {
                    abort(403, "Missing required scope: [{$scope}].");
                }
            }
        }

        return $next($request);
    }
}
