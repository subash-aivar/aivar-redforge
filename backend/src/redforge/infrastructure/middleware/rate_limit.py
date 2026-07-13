"""Rate limiting middleware for authentication endpoints.

Applies sliding-window rate limiting to sensitive endpoints
(login, register, refresh) to prevent brute-force attacks.

Limits:
- Per-IP: 20 requests per minute (protects against distributed attacks)
- Per-user (email): 5 login attempts per minute (protects individual accounts)

Returns HTTP 429 with Retry-After header when exceeded.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from redforge.core.logging import get_logger
from redforge.infrastructure.rate_limiting.contracts import RateLimiter

logger = get_logger(__name__)

# Paths subject to rate limiting
_AUTH_PATHS = frozenset({
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
})

# Limits
_IP_MAX_REQUESTS = 20
_IP_WINDOW_SECONDS = 60
_USER_MAX_REQUESTS = 5
_USER_WINDOW_SECONDS = 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Applies rate limiting to authentication endpoints.

    Uses the injected RateLimiter (protocol-based, swappable).
    Checks per-IP first, then per-user if applicable.
    """

    def __init__(self, app: object, limiter: RateLimiter) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._limiter = limiter

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path not in _AUTH_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        # Per-IP check
        ip_result = await self._limiter.check(
            f"ip:{client_ip}", _IP_MAX_REQUESTS, _IP_WINDOW_SECONDS
        )
        if not ip_result.allowed:
            logger.warning(
                "rate_limit_exceeded",
                key=f"ip:{client_ip}",
                path=request.url.path,
                retry_after=ip_result.retry_after_seconds,
            )
            return self._too_many_requests(ip_result.retry_after_seconds)

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(ip_result.limit)
        response.headers["X-RateLimit-Remaining"] = str(ip_result.remaining)

        return response

    @staticmethod
    def _too_many_requests(retry_after: int) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests. Please try again later.",
                }
            },
            headers={"Retry-After": str(retry_after)},
        )
