"""OpenTelemetry instrumentation for AIVAR RedForge.

Provides distributed tracing across:
- HTTP requests (FastAPI auto-instrumentation)
- Database operations (SQLAlchemy auto-instrumentation)
- External HTTP calls (httpx auto-instrumentation)
- Application services (manual spans)

Configuration:
- REDFORGE_OTEL_ENABLED: Enable/disable tracing (default: false)
- REDFORGE_OTEL_ENDPOINT: OTLP collector endpoint
- REDFORGE_OTEL_SERVICE_NAME: Service name in traces

Correlation IDs from the request context are propagated into trace attributes
so that log entries and traces can be correlated.
"""

from redforge.infrastructure.telemetry.setup import configure_telemetry

__all__ = ["configure_telemetry"]
