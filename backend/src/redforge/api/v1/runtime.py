"""Runtime status and operational management endpoints — Sprint 27.

Provides operators with real-time visibility into the runtime platform:

  GET  /runtime/status        — quick health summary (no auth)
  GET  /runtime/health        — full AggregatedHealth report (no auth)
  GET  /runtime/circuits      — circuit breaker states (no auth)
  GET  /runtime/metrics       — InMemoryMetricsCollector snapshot (no auth)
  GET  /runtime/dlq           — list DLQ entries for the caller's org (auth)
  POST /runtime/dlq/{id}/requeue — operator retry (auth)
  DELETE /runtime/dlq/{id}   — discard poisoned entry (auth)
  GET  /runtime/diagnostics   — full runtime snapshot (auth)

Authentication model:
    Status/health/circuits/metrics are unauthenticated, matching /health
    conventions. These expose no tenant data.
    DLQ endpoints require a valid TenantContext so that list/requeue/discard
    are scoped to the caller's organization (multi-tenant isolation).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from redforge.api.dependencies import (
    get_circuit_registry,
    get_dlq,
    get_health_engine,
    get_lifecycle_coordinator,
    get_metrics_collector,
    get_projection_registry,
    get_replay_worker,
    get_runtime_container,
)
from redforge.api.security import get_tenant_context, require_permission
from redforge.application.platform.dead_letter_queue import DeadLetterEntryNotFoundError
from redforge.core.logging import get_logger
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.api.security import TenantContext
    from redforge.application.platform.circuit_breaker import CircuitBreakerRegistry
    from redforge.application.platform.health_engine import RuntimeHealthEngine
    from redforge.application.platform.lifecycle import GracefulShutdownCoordinator
    from redforge.application.platform.metrics_abstraction import InMemoryMetricsCollector
    from redforge.application.platform.projection_registry import ProjectionRegistry
    from redforge.application.platform.replay_worker import DLQReplayWorker
    from redforge.application.platform.runtime_container import RuntimeContainer
    from redforge.application.platform.runtime_contracts import RuntimeDLQ

router = APIRouter(prefix="/runtime")
logger = get_logger(__name__)


# ── Response models ────────────────────────────────────────────────────────────


class ComponentHealthResponse(BaseModel):
    component_id: str
    component_type: str
    status: str
    message: str
    checked_at: datetime
    details: dict[str, Any] = {}


class RuntimeStatusResponse(BaseModel):
    """Lightweight status summary — no auth required."""
    phase: str
    overall_health: str
    component_count: int
    unhealthy_components: list[str]
    circuit_states: dict[str, str]
    dlq_total_entries: int
    metrics_sample_count: int
    checked_at: datetime


class AggregatedHealthResponse(BaseModel):
    overall_status: str
    components: list[ComponentHealthResponse]
    checked_at: datetime


class MetricSampleResponse(BaseModel):
    name: str
    value: float
    metric_type: str
    labels: dict[str, str]
    sampled_at: datetime


class MetricsSnapshotResponse(BaseModel):
    total_samples: int
    samples: list[MetricSampleResponse]
    snapshot_at: datetime


class DLQEntryResponse(BaseModel):
    entry_id: str
    source_projection: str
    event_id: str
    event_type: str
    error_message: str
    retry_count: int
    organization_id: str
    first_failed_at: datetime
    last_failed_at: datetime


class DLQListResponse(BaseModel):
    entries: list[DLQEntryResponse]
    total: int


class DiagnosticsResponse(BaseModel):
    """Full runtime diagnostics — requires authentication."""
    phase: str
    overall_health: str
    components: list[ComponentHealthResponse]
    circuit_states: dict[str, str]
    startup_hooks: list[str]
    shutdown_hooks: list[str]
    backpressure_in_flight: int
    backpressure_utilization: float
    backpressure_throttled: bool
    checked_at: datetime


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _component_to_response(component: Any) -> ComponentHealthResponse:
    return ComponentHealthResponse(
        component_id=component.component_id,
        component_type=component.component_type,
        status=component.status.value,
        message=component.message,
        checked_at=component.checked_at,
        details=dict(component.details),
    )


def _metric_sample_to_response(sample: Any) -> MetricSampleResponse:
    return MetricSampleResponse(
        name=sample.name,
        value=sample.value,
        metric_type=sample.metric_type.value,
        labels=dict(sample.labels),
        sampled_at=sample.sampled_at,
    )


# ── Unauthenticated endpoints ─────────────────────────────────────────────────


@router.get(
    "/status",
    response_model=RuntimeStatusResponse,
    summary="Runtime platform quick status",
)
async def runtime_status(
    health_engine: RuntimeHealthEngine = Depends(get_health_engine),
    circuit_registry: CircuitBreakerRegistry = Depends(get_circuit_registry),
    dlq: RuntimeDLQ = Depends(get_dlq),
    metrics: InMemoryMetricsCollector = Depends(get_metrics_collector),
    coordinator: GracefulShutdownCoordinator = Depends(get_lifecycle_coordinator),
) -> RuntimeStatusResponse:
    """Quick health summary — suitable for load balancer / monitoring checks."""
    aggregated = await health_engine.aggregate_health()

    unhealthy = [
        c.component_id
        for c in aggregated.components
        if c.status.value != "healthy"
    ]

    total_dlq = await dlq.total_depth()

    return RuntimeStatusResponse(
        phase=coordinator.phase.value,
        overall_health=aggregated.overall_status.value,
        component_count=len(aggregated.components),
        unhealthy_components=unhealthy,
        circuit_states=circuit_registry.all_states(),
        dlq_total_entries=total_dlq,
        metrics_sample_count=metrics.total_samples,
        checked_at=_utc_now(),
    )


@router.get(
    "/health",
    response_model=AggregatedHealthResponse,
    summary="Full aggregated health report",
)
async def runtime_health(
    health_engine: RuntimeHealthEngine = Depends(get_health_engine),
) -> AggregatedHealthResponse:
    """Run all registered health checks concurrently and return results."""
    aggregated = await health_engine.aggregate_health()
    return AggregatedHealthResponse(
        overall_status=aggregated.overall_status.value,
        components=[_component_to_response(c) for c in aggregated.components],
        checked_at=aggregated.checked_at,
    )


@router.get(
    "/circuits",
    response_model=dict[str, str],
    summary="All circuit breaker states",
)
async def circuit_states(
    circuit_registry: CircuitBreakerRegistry = Depends(get_circuit_registry),
) -> dict[str, str]:
    """Return current state of every registered circuit breaker."""
    return circuit_registry.all_states()


@router.get(
    "/metrics",
    response_model=MetricsSnapshotResponse,
    summary="Runtime metrics snapshot",
)
async def metrics_snapshot(
    metrics: InMemoryMetricsCollector = Depends(get_metrics_collector),
    name: str | None = None,
) -> MetricsSnapshotResponse:
    """Return the last N metric samples from the in-memory collector.

    Optionally filter by metric ``name`` query parameter.
    This endpoint exposes the protocol-backed abstraction layer, not
    raw prometheus_client counters.
    """
    samples = metrics.snapshot(name=name)
    return MetricsSnapshotResponse(
        total_samples=metrics.total_samples,
        samples=[_metric_sample_to_response(s) for s in samples],
        snapshot_at=_utc_now(),
    )


# ── Authenticated DLQ endpoints ───────────────────────────────────────────────


@router.get(
    "/dlq",
    response_model=DLQListResponse,
    summary="List DLQ entries for the caller's organization",
)
async def list_dlq_entries(
    tenant: TenantContext = Depends(get_tenant_context),
    dlq: RuntimeDLQ = Depends(get_dlq),
    source_projection: str | None = None,
    max_count: int = 100,
) -> DLQListResponse:
    """List dead-letter entries scoped to the caller's organization.

    Results are filtered by the organization_id from the access token —
    callers cannot access other organizations' DLQ entries.
    """
    entries = await dlq.list(
        organization_id=tenant.organization_id,
        source_projection=source_projection,
        max_count=max_count,
    )
    return DLQListResponse(
        entries=[
            DLQEntryResponse(
                entry_id=e.entry_id,
                source_projection=e.source_projection,
                event_id=e.event_id,
                event_type=e.event_type,
                error_message=e.error_message,
                retry_count=e.retry_count,
                organization_id=e.organization_id,
                first_failed_at=e.first_failed_at,
                last_failed_at=e.last_failed_at,
            )
            for e in entries
        ],
        total=len(entries),
    )


@router.post(
    "/dlq/{entry_id}/requeue",
    response_model=DLQEntryResponse,
    summary="Requeue a DLQ entry for retry",
)
async def requeue_dlq_entry(
    entry_id: str,
    tenant: TenantContext = Depends(get_tenant_context),
    dlq: RuntimeDLQ = Depends(get_dlq),
) -> DLQEntryResponse:
    """Increment retry_count and mark the entry ready for re-processing.

    The entry is not automatically replayed — a separate replay mechanism
    must pick it up. This endpoint increments retry_count and updates
    last_failed_at.
    """
    try:
        entry = await dlq.requeue(entry_id)
    except DeadLetterEntryNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DLQ entry not found: {entry_id}",
        ) from None

    # Verify the entry belongs to the caller's org (multi-tenant guard)
    if entry.organization_id != tenant.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Entry does not belong to your organization",
        )

    logger.info(
        "dlq_entry_requeued",
        entry_id=entry_id,
        retry_count=entry.retry_count,
        organization_id=tenant.organization_id,
    )

    return DLQEntryResponse(
        entry_id=entry.entry_id,
        source_projection=entry.source_projection,
        event_id=entry.event_id,
        event_type=entry.event_type,
        error_message=entry.error_message,
        retry_count=entry.retry_count,
        organization_id=entry.organization_id,
        first_failed_at=entry.first_failed_at,
        last_failed_at=entry.last_failed_at,
    )


@router.delete(
    "/dlq/{entry_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Permanently discard a DLQ entry",
)
async def discard_dlq_entry(
    entry_id: str,
    tenant: TenantContext = Depends(get_tenant_context),
    dlq: RuntimeDLQ = Depends(get_dlq),
) -> None:
    """Permanently remove an entry from the dead-letter queue.

    Use when the event is confirmed invalid and should never be retried.
    This action is irreversible.
    """
    # Check entry exists and belongs to caller's org before discarding
    entries = await dlq.list(organization_id=tenant.organization_id)
    if not any(e.entry_id == entry_id for e in entries):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DLQ entry not found: {entry_id}",
        )

    try:
        await dlq.discard(entry_id)
    except DeadLetterEntryNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DLQ entry not found: {entry_id}",
        ) from None

    logger.info(
        "dlq_entry_discarded",
        entry_id=entry_id,
        organization_id=tenant.organization_id,
    )


@router.get(
    "/diagnostics",
    response_model=DiagnosticsResponse,
    summary="Full runtime diagnostics (authenticated)",
)
async def runtime_diagnostics(
    tenant: TenantContext = Depends(get_tenant_context),
    runtime: RuntimeContainer = Depends(get_runtime_container),
) -> DiagnosticsResponse:
    """Full runtime snapshot including backpressure and hook registrations.

    Requires authentication. Intended for operators and internal tooling.
    """
    aggregated = await runtime.health_engine.aggregate_health()
    coordinator = runtime.coordinator

    return DiagnosticsResponse(
        phase=coordinator.phase.value,
        overall_health=aggregated.overall_status.value,
        components=[_component_to_response(c) for c in aggregated.components],
        circuit_states=runtime.circuit_registry.all_states(),
        startup_hooks=coordinator.startup_hook_names(),
        shutdown_hooks=coordinator.shutdown_hook_names(),
        backpressure_in_flight=runtime.backpressure.queue_depth,
        backpressure_utilization=runtime.backpressure.utilization,
        backpressure_throttled=runtime.backpressure.is_throttled,
        checked_at=_utc_now(),
    )


# ── Circuit reset (authenticated, admin operation) ────────────────────────────


@router.post(
    "/circuits/{name}/reset",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Reset a circuit breaker to CLOSED state",
)
async def reset_circuit_breaker(
    name: str,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    circuit_registry: CircuitBreakerRegistry = Depends(get_circuit_registry),
) -> None:
    """Force-reset a named circuit breaker to CLOSED state.

    Restricted to OWNER and ADMIN roles (ORG_MANAGE permission). MEMBER and
    VIEWER roles receive 403 Forbidden.

    Use with caution: resetting OPEN circuits bypasses the recovery timeout
    and may cause immediate traffic to a still-unhealthy dependency.
    """
    cb = circuit_registry.get(name)
    if cb is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Circuit breaker not found: {name!r}",
        )
    cb.reset()
    logger.info(
        "circuit_reset",
        circuit_name=name,
        organization_id=tenant.organization_id,
    )


# ── Projection diagnostics (Sprint 30) ───────────────────────────────────────


class ProjectionInfoResponse(BaseModel):
    name: str
    type: str


class ProjectionsListResponse(BaseModel):
    count: int
    projections: list[ProjectionInfoResponse]


class ProjectionDetailResponse(BaseModel):
    name: str
    type: str
    checkpoint_position: int


class ReplayStatusResponse(BaseModel):
    worker_running: bool
    replayed: int
    failed: int
    skipped: int
    in_flight: int


class CheckpointResponse(BaseModel):
    projection_name: str
    last_global_position: int


class CheckpointsResponse(BaseModel):
    projections: list[CheckpointResponse]
    total: int


@router.get(
    "/projections",
    response_model=ProjectionsListResponse,
    summary="List all registered projections",
)
async def list_projections(
    registry: ProjectionRegistry = Depends(get_projection_registry),
) -> ProjectionsListResponse:
    """Return every projection registered in the runtime projection registry."""
    return ProjectionsListResponse(
        count=registry.count,
        projections=[
            ProjectionInfoResponse(name=p["name"], type=p["type"])
            for p in registry.info()
        ],
    )


@router.get(
    "/projections/{name}",
    response_model=ProjectionDetailResponse,
    summary="Detail for a single registered projection",
)
async def get_projection(
    name: str,
    registry: ProjectionRegistry = Depends(get_projection_registry),
) -> ProjectionDetailResponse:
    """Return metadata for one projection by name."""
    matches = [p for p in registry.info() if p["name"] == name]
    if not matches:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Projection not found: {name!r}",
        )
    proj_info = matches[0]
    return ProjectionDetailResponse(
        name=proj_info["name"],
        type=proj_info["type"],
        checkpoint_position=-1,
    )


@router.get(
    "/replay/status",
    response_model=ReplayStatusResponse,
    summary="DLQ replay worker live statistics",
)
async def replay_status(
    worker: DLQReplayWorker | None = Depends(get_replay_worker),
) -> ReplayStatusResponse:
    """Return real-time statistics from the DLQ replay worker."""
    if worker is None:
        return ReplayStatusResponse(
            worker_running=False,
            replayed=0,
            failed=0,
            skipped=0,
            in_flight=0,
        )
    stats = worker.stats()
    return ReplayStatusResponse(
        worker_running=worker.is_running,
        replayed=int(stats.get("replayed", 0)),
        failed=int(stats.get("failed", 0)),
        skipped=int(stats.get("skipped", 0)),
        in_flight=0,
    )


# ── Checkpoint TTL cache (DEBT-S31-5) ─────────────────────────────────────────
# Avoid a live DB round-trip on every polling call. Cache for 30 seconds.
_checkpoint_cache: dict[str, int] = {}
_checkpoint_cache_ts: float = 0.0
_CHECKPOINT_CACHE_TTL_S: float = 30.0


@router.get(
    "/checkpoints",
    response_model=CheckpointsResponse,
    summary="Live checkpoint positions from PostgreSQL for all registered projections",
)
async def list_checkpoints(
    registry: ProjectionRegistry = Depends(get_projection_registry),
    container: Any = Depends(get_runtime_container),
) -> CheckpointsResponse:
    """Return durable checkpoint positions queried from PostgreSQL.

    Results are cached for 30 seconds to avoid a DB round-trip on every
    polling call (DEBT-S31-5). Falls back to -1 without a DB connection.
    """
    global _checkpoint_cache, _checkpoint_cache_ts

    checkpoint_map: dict[str, int] = {name: -1 for name in registry.projection_names}

    now = time.monotonic()
    if container.session_factory is not None:
        if now - _checkpoint_cache_ts < _CHECKPOINT_CACHE_TTL_S and _checkpoint_cache:
            # Serve from cache
            for name in checkpoint_map:
                if name in _checkpoint_cache:
                    checkpoint_map[name] = _checkpoint_cache[name]
        else:
            try:
                from redforge.infrastructure.platform.checkpoint_repository import (
                    PostgreSQLCheckpointRepository,
                )

                async with container.session_factory() as session:
                    cp_repo = PostgreSQLCheckpointRepository(session)
                    stored = await cp_repo.list_checkpoints("")
                    for cp in stored:
                        if cp.projection_name in checkpoint_map:
                            checkpoint_map[cp.projection_name] = cp.last_global_position
                # Refresh cache
                _checkpoint_cache = dict(checkpoint_map)
                _checkpoint_cache_ts = now
            except Exception:
                logger.warning("checkpoints_db_query_failed")

    projections = [
        CheckpointResponse(projection_name=name, last_global_position=pos)
        for name, pos in checkpoint_map.items()
    ]
    return CheckpointsResponse(projections=projections, total=len(projections))
