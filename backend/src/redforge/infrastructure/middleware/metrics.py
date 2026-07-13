"""Prometheus metrics middleware.

Exposes standard RED metrics (Rate, Errors, Duration) for every HTTP endpoint.
Metrics are collected per method+path+status and exposed at /metrics.
"""

import time

from prometheus_client import Counter, Histogram
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# ─── Metric Definitions ──────────────────────────────────────────────────────

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status_code"],
)

REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

EXCEPTIONS_TOTAL = Counter(
    "http_exceptions_total",
    "Total unhandled exceptions",
    ["method", "path", "exception_type"],
)


def _normalize_path(path: str) -> str:
    """Normalize path to prevent cardinality explosion from path parameters.

    Replaces ULID/UUID-like segments with {id} placeholder.
    """
    parts = path.split("/")
    normalized = []
    for part in parts:
        # ULID (26 chars) or UUID-like
        if len(part) >= 20 and part.isalnum():
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/".join(normalized)


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Collects HTTP request metrics for Prometheus scraping.

    Tracks: request count, duration histogram, exception counter.
    Path parameters are normalized to prevent label cardinality explosion.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip metrics endpoint itself to avoid recursion
        if request.url.path == "/metrics":
            return await call_next(request)

        method = request.method
        path = _normalize_path(request.url.path)
        start = time.perf_counter()

        try:
            response = await call_next(request)
            duration = time.perf_counter() - start

            REQUEST_COUNT.labels(
                method=method,
                path=path,
                status_code=response.status_code,
            ).inc()
            REQUEST_DURATION.labels(method=method, path=path).observe(duration)

            return response

        except Exception as exc:
            duration = time.perf_counter() - start
            EXCEPTIONS_TOTAL.labels(
                method=method,
                path=path,
                exception_type=type(exc).__name__,
            ).inc()
            REQUEST_COUNT.labels(method=method, path=path, status_code=500).inc()
            REQUEST_DURATION.labels(method=method, path=path).observe(duration)
            raise
