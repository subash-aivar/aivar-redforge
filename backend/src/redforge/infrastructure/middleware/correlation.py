"""Correlation ID middleware.

Extracts or generates a unique request ID for every incoming request.
The ID is bound to structlog's context so it appears in all log entries
produced during that request's lifecycle. It is also returned in the
response headers for client-side tracing.
"""

from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from redforge.core.logging import correlation_id_ctx, request_id_ctx

REQUEST_ID_HEADER = "X-Request-ID"
CORRELATION_ID_HEADER = "X-Correlation-ID"


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Injects request and correlation IDs into the request context.

    - X-Request-ID: Unique per request. Generated if not provided by the client.
    - X-Correlation-ID: Propagated from the client to enable distributed tracing.
      Falls back to the request ID if not provided.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER, str(uuid4()))
        correlation_id = request.headers.get(CORRELATION_ID_HEADER, request_id)

        request_id_ctx.set(request_id)
        correlation_id_ctx.set(correlation_id)

        response = await call_next(request)

        response.headers[REQUEST_ID_HEADER] = request_id
        response.headers[CORRELATION_ID_HEADER] = correlation_id

        return response
