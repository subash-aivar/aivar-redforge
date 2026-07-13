"""Structured logging configuration using structlog.

Provides JSON-formatted logs in production and human-readable colored output
in development. Context variables (request_id, correlation_id) are automatically
included in every log entry via contextvars-based binding.
"""

import logging
import sys
from contextvars import ContextVar

import structlog

# Context variables for request-scoped log context
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
correlation_id_ctx: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def _add_request_context(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Structlog processor that injects request context from contextvars."""
    request_id = request_id_ctx.get()
    if request_id is not None:
        event_dict["request_id"] = request_id

    correlation_id = correlation_id_ctx.get()
    if correlation_id is not None:
        event_dict["correlation_id"] = correlation_id

    return event_dict


def configure_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Configure structlog and stdlib logging for the application.

    Args:
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Output format — 'json' for production, 'console' for development.
    """
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        _add_request_context,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if log_format == "json":
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            renderer,
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(log_level.upper())
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a bound structlog logger instance.

    Args:
        name: Optional logger name. Typically the module's __name__.

    Returns:
        A bound logger with the application's configured processors.
    """
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
