"""Security Operations Command Center REST API — M15.

Every route is tenant-scoped via TenantContext; organization_id is
NEVER accepted from the client, matching every other M10-M14 router in
this codebase. A single read permission (Permission.
SECURITY_OPERATIONS_READ) gates both REST reads and the SSE stream —
this bounded context owns nothing and never mutates any other bounded
context's state; there is no write/publish endpoint anywhere in this
router by design (see application/security_operations/__init__.py's
own scope statement).

Route ordering matters: literal-path routes (`/events/stream`) are
registered before `/executions/{execution_id}` so they are never
swallowed by a path parameter.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from redforge.api.dependencies import (
    get_execution_telemetry_service,
    get_runtime_operations_service,
    get_security_change_feed_service,
    get_security_operations_stream_service,
    get_security_operations_summary_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission
from redforge.domain.security_operations.value_objects import (
    STREAM_HEARTBEAT_INTERVAL_SECONDS,
    STREAM_POLL_INTERVAL_SECONDS,
    BoundedPeriod,
    OperationalImportance,
    SourceDomain,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from redforge.application.security_operations.change_feed_service import (
        SecurityChangeFeedService,
    )
    from redforge.application.security_operations.execution_telemetry_service import (
        ExecutionTelemetryService,
    )
    from redforge.application.security_operations.runtime_operations_service import (
        RuntimeOperationsService,
    )
    from redforge.application.security_operations.stream_service import (
        SecurityOperationsStreamService,
    )
    from redforge.application.security_operations.summary_service import (
        SecurityOperationsSummaryDTO,
        SecurityOperationsSummaryService,
    )
    from redforge.domain.security_operations.operational_event import OperationalEvent

# Two routers sharing the same `/security-operations` prefix so that
# edition membership can be assigned per-router (see api/v1/__init__.py's
# `_Registration.editions`) without changing a single URL or Full
# RedForge's response contract:
#   - `common_router`: summary/changes/events/events-stream/runtime —
#     available to both editions (with edition-aware data composition
#     applied inside the services themselves, not here).
#   - `executions_router`: a pure M11 ValidationExecution projection with
#     zero Network Defense relevance — Full-only, absent (404) from the
#     Network Defense mounted API surface.
# `router` remains the combined router (both sub-routers, in the same
# route order) for backward compatibility with call sites/tests that
# still import and mount `security_operations.router` directly.
common_router = APIRouter(prefix="/security-operations", tags=["security-operations"])
executions_router = APIRouter(prefix="/security-operations", tags=["security-operations"])


# ─── Response models ───────────────────────────────────────────────────────


class OperationalEventResponse(BaseModel):
    cursor: str
    event_id: str
    organization_id: str
    source_domain: str
    importance: str
    title: str
    summary: str
    entity_type: str
    entity_id: str
    occurred_at: str
    schema_version: int

    @classmethod
    def from_event(cls, e: OperationalEvent) -> OperationalEventResponse:
        return cls(
            cursor=e.cursor, event_id=e.event_id, organization_id=e.organization_id,
            source_domain=str(e.source_domain),
            importance=str(e.importance), title=e.title, summary=e.summary,
            entity_type=e.entity_type, entity_id=e.entity_id, occurred_at=e.occurred_at,
            schema_version=e.schema_version,
        )


class SummaryResponse(BaseModel):
    period: str
    canonical_assets: int
    critical_high_conditions: int
    active_correlations: int
    runtime_unhealthy_components: int
    # Full-only fields — real integers for the "full" edition, `null` for
    # "network_defense" (never fabricated as 0; see SecurityOperationsSummaryDTO).
    active_targets: int | None = None
    active_continuous_validation_policies: int | None = None
    validations_running: int | None = None
    validations_blocked_in_period: int | None = None
    validations_failed_in_period: int | None = None
    drift_events_in_period: int | None = None

    @classmethod
    def from_dto(cls, dto: SecurityOperationsSummaryDTO) -> SummaryResponse:
        return cls(**asdict(dto))


class ExecutionTelemetrySummaryResponse(BaseModel):
    id: str
    organization_id: str
    target_id: str
    trigger: str
    continuous_policy_id: str | None
    profile: str
    state: str
    phase: str
    latest_event_title: str | None
    created_at: str
    started_at: str | None
    completed_at: str | None


class TelemetryTimelineEntryResponse(BaseModel):
    phase: str
    event_type: str
    title: str
    occurred_at: str


class ExecutionTelemetryDetailResponse(BaseModel):
    summary: ExecutionTelemetrySummaryResponse
    timeline: list[TelemetryTimelineEntryResponse]
    result_summary: str


class RuntimeComponentResponse(BaseModel):
    component_id: str
    status: str
    message: str
    checked_at: str


# ─── Summary / change feed ─────────────────────────────────────────────────


@common_router.get("/summary", response_model=SummaryResponse)
async def get_summary(
    period: BoundedPeriod = Query(default=BoundedPeriod.TWENTY_FOUR_HOURS),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: SecurityOperationsSummaryService = Depends(get_security_operations_summary_service),
) -> SummaryResponse:
    dto = await service.get_summary(tenant.organization_id, period)
    return SummaryResponse.from_dto(dto)


@common_router.get("/changes", response_model=list[OperationalEventResponse])
async def list_changes(
    period: BoundedPeriod = Query(default=BoundedPeriod.TWENTY_FOUR_HOURS),
    source_domain: SourceDomain | None = Query(default=None),
    importance: OperationalImportance | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: SecurityChangeFeedService = Depends(get_security_change_feed_service),
) -> list[OperationalEventResponse]:
    events = await service.list_changes(
        tenant.organization_id, period, source_domain, importance, entity_id, limit, offset,
    )
    return [OperationalEventResponse.from_event(e) for e in events]


@common_router.get("/events", response_model=list[OperationalEventResponse])
async def list_events(
    since_cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: SecurityOperationsStreamService = Depends(get_security_operations_stream_service),
) -> list[OperationalEventResponse]:
    """A non-streaming, JSON-polling variant of the same cursor-based
    feed the SSE endpoint below serves — for clients that prefer
    request/response polling over an open stream."""
    events = await service.poll(tenant.organization_id, since_cursor, limit)
    return [OperationalEventResponse.from_event(e) for e in events]


# ─── SSE stream ─────────────────────────────────────────────────────────────


def _sse_frame(event: OperationalEvent) -> str:
    payload = OperationalEventResponse.from_event(event).model_dump()
    return f"id: {event.cursor}\nevent: operational_event\ndata: {json.dumps(payload)}\n\n"


@common_router.get("/events/stream")
async def stream_events(
    request: Request,
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: SecurityOperationsStreamService = Depends(get_security_operations_stream_service),
) -> StreamingResponse:
    """Durable, tenant-scoped, cursor-resumable operational event
    stream. Resume is governed entirely by `Last-Event-ID` mapped
    straight onto the composite cursor `poll()` already understands — a
    malformed/unknown cursor safely resets to reading from the
    beginning rather than ever producing a 500 (see stream_service.
    poll()'s own docstring). No per-client unbounded in-memory queue: each
    iteration opens one short-lived, bounded DB query via poll(), so an
    idle or slow consumer holds no database connection between polls."""
    organization_id = tenant.organization_id

    async def _generate() -> AsyncIterator[str]:
        cursor = last_event_id
        seconds_since_heartbeat = 0.0
        while True:
            if await request.is_disconnected():
                break
            events = await service.poll(organization_id, cursor)
            if events:
                for event in events:
                    yield _sse_frame(event)
                    cursor = event.cursor
                seconds_since_heartbeat = 0.0
            else:
                seconds_since_heartbeat += STREAM_POLL_INTERVAL_SECONDS
                if seconds_since_heartbeat >= STREAM_HEARTBEAT_INTERVAL_SECONDS:
                    yield ": heartbeat\n\n"
                    seconds_since_heartbeat = 0.0
            await asyncio.sleep(STREAM_POLL_INTERVAL_SECONDS)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Execution telemetry ───────────────────────────────────────────────────


@executions_router.get("/executions", response_model=list[ExecutionTelemetrySummaryResponse])
async def list_executions(
    state: str | None = Query(default=None),
    trigger: str | None = Query(default=None),
    target_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: ExecutionTelemetryService = Depends(get_execution_telemetry_service),
) -> list[ExecutionTelemetrySummaryResponse]:
    summaries = await service.list_executions(
        tenant.organization_id, state, trigger, target_id, limit, offset,
    )
    return [ExecutionTelemetrySummaryResponse(**asdict(s)) for s in summaries]


@executions_router.get(
    "/executions/{execution_id}", response_model=ExecutionTelemetryDetailResponse,
)
async def get_execution_detail(
    execution_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: ExecutionTelemetryService = Depends(get_execution_telemetry_service),
) -> ExecutionTelemetryDetailResponse:
    detail = await service.get_detail(tenant.organization_id, execution_id)
    return ExecutionTelemetryDetailResponse(
        summary=ExecutionTelemetrySummaryResponse(**asdict(detail.summary)),
        timeline=[TelemetryTimelineEntryResponse(**asdict(t)) for t in detail.timeline],
        result_summary=detail.result_summary,
    )


# ─── Runtime operations ─────────────────────────────────────────────────────


@common_router.get("/runtime", response_model=list[RuntimeComponentResponse])
async def list_runtime_components(
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: RuntimeOperationsService = Depends(get_runtime_operations_service),
) -> list[RuntimeComponentResponse]:
    components = await service.list_components()
    return [RuntimeComponentResponse(**asdict(c)) for c in components]


# Combined router — every route above, in the same order, for backward
# compatibility with call sites that mount `security_operations.router`
# directly (e.g. backend/tests/api/test_security_operations_isolation.py).
# Edition-aware exposure is decided at the registry level (api/v1/__init__.py)
# by registering `common_router`/`executions_router` separately, never here.
router = APIRouter()
router.include_router(common_router)
router.include_router(executions_router)
