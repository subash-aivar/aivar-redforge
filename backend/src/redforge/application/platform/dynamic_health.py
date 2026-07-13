"""Dynamic health probes — Sprint 28.

Replaces the make_static_health_checker stubs from Sprint 27 with probes
that actually test live system components. Each probe returns a ComponentHealth
immediately from an async check rather than a pre-configured constant.

Design rules:
- Probes are thin coroutine factories — no state, no side effects on failure.
- All exceptions are caught and reported as UNHEALTHY (never raise into the engine).
- Probes import infrastructure types only within the factory body so that
  application-layer callers can import this module without pulling in SQLAlchemy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.application.platform.runtime_contracts import (
    ComponentHealth,
    HealthStatus,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from redforge.application.continuous_validation.scheduler_worker import (
        ContinuousValidationSchedulerWorker,
    )
    from redforge.application.network_security.scheduler_worker import (
        NetworkMonitoringSchedulerWorker,
    )
    from redforge.application.platform.replay_worker import DLQReplayWorker
    from redforge.application.platform.runtime_contracts import RuntimeDLQ

_PERSISTENCE = "persistence"
_PLATFORM = "platform"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def make_database_health_probe(engine: AsyncEngine) -> Any:
    """Live database probe — runs SELECT 1 via the async engine."""
    from sqlalchemy import text

    async def _probe() -> ComponentHealth:
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return ComponentHealth(
                component_id="database",
                component_type=_PERSISTENCE,
                status=HealthStatus.HEALTHY,
                message="Database reachable",
                checked_at=_utc_now(),
            )
        except Exception as exc:
            return ComponentHealth(
                component_id="database",
                component_type=_PERSISTENCE,
                status=HealthStatus.UNHEALTHY,
                message=f"Database unreachable: {type(exc).__name__}",
                checked_at=_utc_now(),
            )

    return _probe


def make_replay_worker_health_probe(worker: DLQReplayWorker) -> Any:
    """Health probe for the DLQ replay worker background task."""
    async def _probe() -> ComponentHealth:
        running = worker.is_running
        return ComponentHealth(
            component_id="replay_worker",
            component_type=_PLATFORM,
            status=HealthStatus.HEALTHY if running else HealthStatus.DEGRADED,
            message="Replay worker running" if running else "Replay worker stopped",
            checked_at=_utc_now(),
        )

    return _probe


def make_continuous_validation_scheduler_health_probe(
    worker: ContinuousValidationSchedulerWorker,
) -> Any:
    """Health probe for the continuous validation scheduler background task."""
    async def _probe() -> ComponentHealth:
        running = worker.is_running
        return ComponentHealth(
            component_id="continuous_validation_scheduler",
            component_type=_PLATFORM,
            status=HealthStatus.HEALTHY if running else HealthStatus.DEGRADED,
            message=(
                "Continuous validation scheduler running" if running
                else "Continuous validation scheduler stopped"
            ),
            checked_at=_utc_now(),
        )

    return _probe


def make_network_monitoring_scheduler_health_probe(
    worker: NetworkMonitoringSchedulerWorker,
) -> Any:
    """Health probe for the M16 network monitoring scheduler background
    task — identical shape to the M14 continuous validation scheduler
    probe above."""
    async def _probe() -> ComponentHealth:
        running = worker.is_running
        return ComponentHealth(
            component_id="network_monitoring_scheduler",
            component_type=_PLATFORM,
            status=HealthStatus.HEALTHY if running else HealthStatus.DEGRADED,
            message=(
                "Network monitoring scheduler running" if running
                else "Network monitoring scheduler stopped"
            ),
            checked_at=_utc_now(),
        )

    return _probe


def make_dlq_depth_health_probe(
    dlq: RuntimeDLQ,
    warn_threshold: int = 1_000,
    critical_threshold: int = 9_000,
) -> Any:
    """Health probe that degrades/fails when DLQ depth exceeds thresholds."""
    async def _probe() -> ComponentHealth:
        try:
            depth = await dlq.total_depth()
        except Exception as exc:
            return ComponentHealth(
                component_id="dlq",
                component_type=_PLATFORM,
                status=HealthStatus.UNHEALTHY,
                message=f"DLQ depth check failed: {type(exc).__name__}",
                checked_at=_utc_now(),
            )

        if depth >= critical_threshold:
            s = HealthStatus.UNHEALTHY
            msg = f"DLQ critically full: {depth} entries"
        elif depth >= warn_threshold:
            s = HealthStatus.DEGRADED
            msg = f"DLQ elevated: {depth} entries"
        else:
            s = HealthStatus.HEALTHY
            msg = f"DLQ normal: {depth} entries"

        return ComponentHealth(
            component_id="dlq",
            component_type=_PLATFORM,
            status=s,
            message=msg,
            checked_at=_utc_now(),
        )

    return _probe
