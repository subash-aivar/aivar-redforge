"""OpenTelemetry setup and configuration.

Initializes the tracer provider, span processors, and exporters.
Auto-instruments FastAPI, SQLAlchemy, and httpx when enabled.

Zero business logic modifications — purely infrastructure concern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from redforge.core.logging import get_logger

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = get_logger(__name__)


def configure_telemetry(
    app: FastAPI,
    *,
    enabled: bool = False,
    service_name: str = "redforge-backend",
    otlp_endpoint: str | None = None,
) -> None:
    """Configure OpenTelemetry tracing for the application.

    Args:
        app: FastAPI application to instrument
        enabled: Whether tracing is active (disabled = no-op tracer)
        service_name: Service name for traces
        otlp_endpoint: OTLP gRPC collector endpoint (e.g., "http://localhost:4317")
    """
    if not enabled:
        logger.info("telemetry_disabled", service_name=service_name)
        return

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": "0.1.0",
            "deployment.environment": "production",
        }
    )

    provider = TracerProvider(resource=resource)

    # Configure exporter
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info(
                "telemetry_otlp_configured",
                endpoint=otlp_endpoint,
                service_name=service_name,
            )
        except Exception as exc:
            logger.warning("telemetry_otlp_failed", error=str(exc))
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        # Fallback: console exporter for local development
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)

    # Auto-instrument FastAPI (HTTP spans)
    FastAPIInstrumentor.instrument_app(app)

    # Auto-instrument httpx (outgoing HTTP calls)
    HTTPXClientInstrumentor().instrument()

    # Auto-instrument SQLAlchemy (DB spans)
    SQLAlchemyInstrumentor().instrument(enable_commenter=True)

    logger.info(
        "telemetry_configured",
        service_name=service_name,
        endpoint=otlp_endpoint or "console",
        instrumentors=["fastapi", "httpx", "sqlalchemy"],
    )


def get_tracer(name: str) -> trace.Tracer:
    """Get a tracer instance for creating custom spans.

    Usage in application services:
        tracer = get_tracer(__name__)
        with tracer.start_as_current_span("operation_name") as span:
            span.set_attribute("key", "value")
            # ... business logic
    """
    return trace.get_tracer(name)
