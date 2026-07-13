"""Application-layer span helpers for OpenTelemetry.

Provides a lightweight decorator and context manager for creating
traces in application services, repositories, and providers without
leaking OpenTelemetry imports into the domain or application layer.

Usage in services:
    from redforge.infrastructure.telemetry.spans import traced

    @traced("validation.schedule")
    async def schedule(self, ...): ...

Usage for fine-grained spans:
    from redforge.infrastructure.telemetry.spans import span

    async def complex_operation(self):
        with span("risk.calculate", attributes={"target_id": target_id}):
            ...
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any, TypeVar

from opentelemetry import trace

from redforge.core.logging import correlation_id_ctx, request_id_ctx

F = TypeVar("F", bound=Callable[..., Any])

_tracer = trace.get_tracer("redforge.application")


def traced(operation_name: str) -> Callable[[F], F]:
    """Decorator that wraps an async function in an OpenTelemetry span.

    Automatically adds correlation_id and request_id as span attributes.
    Records exceptions as span events.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            with _tracer.start_as_current_span(operation_name) as current_span:
                # Inject correlation context into span
                req_id = request_id_ctx.get()
                corr_id = correlation_id_ctx.get()
                if req_id:
                    current_span.set_attribute("request.id", req_id)
                if corr_id:
                    current_span.set_attribute("correlation.id", corr_id)

                try:
                    result = await func(*args, **kwargs)
                    current_span.set_status(trace.StatusCode.OK)
                    return result
                except Exception as exc:
                    current_span.set_status(
                        trace.StatusCode.ERROR, str(exc)
                    )
                    current_span.record_exception(exc)
                    raise

        return wrapper  # type: ignore[return-value]

    return decorator


@contextmanager
def span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Any:
    """Context manager for creating a child span with attributes.

    Usage:
        with span("db.query", attributes={"table": "organizations"}):
            await session.execute(...)
    """
    with _tracer.start_as_current_span(name) as current_span:
        if attributes:
            for key, value in attributes.items():
                current_span.set_attribute(key, str(value))

        # Always inject correlation context
        req_id = request_id_ctx.get()
        corr_id = correlation_id_ctx.get()
        if req_id:
            current_span.set_attribute("request.id", req_id)
        if corr_id:
            current_span.set_attribute("correlation.id", corr_id)

        yield current_span
