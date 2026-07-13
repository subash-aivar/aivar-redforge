"""Request logging middleware.

Logs every HTTP request with method, path, status code, and duration.
Uses structlog's bound context so request_id and correlation_id are
automatically included without explicit passing.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from redforge.core.logging import get_logger

logger = get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs request/response pairs with timing information.

    Log entries include method, path, status code, and duration in milliseconds.
    Request and correlation IDs are injected by the CorrelationMiddleware and
    appear automatically via structlog context.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start_time = time.perf_counter()

        response = await call_next(request)

        duration_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=request.client.host if request.client else None,
        )

        return response
