"""Observability helpers for M26 Phase 8 platform orchestration.

Never log secrets or credential reference payloads — only opaque IDs.
Orchestration runs persist as the operational audit trail.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def new_operation_id() -> str:
    """Generate a short opaque operation id for run correlation."""
    return f"op_{uuid.uuid4().hex[:16]}"


def bind_run_context(
    *,
    organization_id: str,
    operation_id: str,
    run_id: str = "",
    correlation_id: str = "",
    request_id: str = "",
    step: str = "",
) -> dict[str, str]:
    """Return a safe structured-log context (no secrets)."""
    ctx: dict[str, str] = {
        "organization_id": organization_id,
        "operation_id": operation_id,
    }
    if run_id:
        ctx["run_id"] = run_id
    if correlation_id:
        ctx["correlation_id"] = correlation_id
    if request_id:
        ctx["request_id"] = request_id
    if step:
        ctx["step"] = step
    # Clear prior keys so tests / sequential runs do not leak context.
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(**ctx)
    return ctx


@contextmanager
def step_timer(step_name: str) -> Iterator[dict[str, Any]]:
    """Context manager that records wall-clock duration for a pipeline step."""
    started = time.perf_counter()
    meta: dict[str, Any] = {"step_name": step_name, "duration_ms": 0.0}
    try:
        yield meta
    finally:
        meta["duration_ms"] = round((time.perf_counter() - started) * 1000.0, 3)


def log_step(
    *,
    step_name: str,
    status: str,
    operation_id: str,
    duration_ms: float | None = None,
    error: str | None = None,
) -> None:
    """Emit a structured step log without credential material."""
    payload: dict[str, Any] = {
        "step_name": step_name,
        "status": status,
        "operation_id": operation_id,
    }
    if duration_ms is not None:
        payload["duration_ms"] = duration_ms
    if error:
        # Truncate; never include raw exception args that may contain secrets
        payload["error"] = error[:500]
    logger.info("cloud_platform.step", **payload)
