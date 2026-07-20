"""M26 Phase 6 Runtime Visibility APIs."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_runtime_ingestion_service,
    get_runtime_query_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.runtime.dtos import IngestRuntimeEventsCommand
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.runtime.ingestion_service import (
        RuntimeIngestionService,
    )
    from redforge.application.cloud_security.runtime.query_service import RuntimeQueryService

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class IngestRuntimeEventsRequest(BaseModel):
    cloud_account_id: UUID
    events: list[dict[str, Any]] = Field(default_factory=list)
    source: str | None = None


class IngestResultResponse(BaseModel):
    organization_id: str
    accepted: int
    inserted: int
    skipped_duplicates: int
    event_ids: list[str] = Field(default_factory=list)


class RuntimeEventResponse(BaseModel):
    event_id: UUID
    organization_id: str
    cloud_account_id: UUID
    event_type: str
    source: str
    severity: str
    outcome: str
    event_time: str
    ingested_at: str
    event_name: str
    provider_event_id: str
    source_ip: str
    target_resource: str
    identity: dict[str, Any] = Field(default_factory=dict)
    host: dict[str, Any] = Field(default_factory=dict)
    container: dict[str, Any] = Field(default_factory=dict)
    correlation_refs: dict[str, Any] = Field(default_factory=dict)
    cspm_snapshot: dict[str, Any] = Field(default_factory=dict)


class RuntimeProcessResponse(BaseModel):
    process_id: UUID
    organization_id: str
    runtime_event_id: UUID
    process_name: str
    executable_path: str
    pid: int | None
    parent_pid: int | None
    command_line: str
    user_name: str
    created_at: str


class RuntimeNetworkConnectionResponse(BaseModel):
    connection_id: UUID
    organization_id: str
    runtime_event_id: UUID
    direction: str
    protocol: str
    local_address: str
    local_port: int | None
    remote_address: str
    remote_port: int | None
    created_at: str


class RuntimeSummaryResponse(BaseModel):
    organization_id: str
    total_events: int
    by_event_type: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    process_count: int
    connection_count: int


def _event_response(dto: Any) -> RuntimeEventResponse:
    return RuntimeEventResponse(
        event_id=UUID(dto.event_id),
        organization_id=dto.organization_id,
        cloud_account_id=UUID(dto.cloud_account_id),
        event_type=dto.event_type,
        source=dto.source,
        severity=dto.severity,
        outcome=dto.outcome,
        event_time=dto.event_time.isoformat(),
        ingested_at=dto.ingested_at.isoformat(),
        event_name=dto.event_name,
        provider_event_id=dto.provider_event_id,
        source_ip=dto.source_ip,
        target_resource=dto.target_resource,
        identity=dict(dto.identity),
        host=dict(dto.host),
        container=dict(dto.container),
        correlation_refs=dict(dto.correlation_refs),
        cspm_snapshot=dict(dto.cspm_snapshot),
    )


@router.post(
    "/runtime/events/ingest",
    response_model=IngestResultResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_runtime_events(
    body: IngestRuntimeEventsRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: RuntimeIngestionService = Depends(get_runtime_ingestion_service),
) -> IngestResultResponse:
    result = await service.ingest(
        IngestRuntimeEventsCommand(
            organization_id=tenant.organization_id,
            cloud_account_id=body.cloud_account_id,
            events=list(body.events),
            source=body.source,
        )
    )
    return IngestResultResponse(
        organization_id=result.organization_id,
        accepted=result.accepted,
        inserted=result.inserted,
        skipped_duplicates=result.skipped_duplicates,
        event_ids=list(result.event_ids),
    )


@router.get("/runtime/events", response_model=list[RuntimeEventResponse])
async def list_runtime_events(
    since: datetime | None = Query(None),
    event_type: str | None = Query(None),
    source: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RuntimeQueryService = Depends(get_runtime_query_service),
) -> list[RuntimeEventResponse]:
    items = await service.list_events(
        tenant.organization_id,
        since=since,
        event_type=event_type,
        source=source,
        limit=limit,
        offset=offset,
    )
    return [_event_response(item) for item in items]


@router.get("/runtime/events/{event_id}", response_model=RuntimeEventResponse)
async def get_runtime_event(
    event_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RuntimeQueryService = Depends(get_runtime_query_service),
) -> RuntimeEventResponse:
    dto = await service.get_event(tenant.organization_id, event_id)
    return _event_response(dto)


@router.get("/runtime/processes", response_model=list[RuntimeProcessResponse])
async def list_runtime_processes(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RuntimeQueryService = Depends(get_runtime_query_service),
) -> list[RuntimeProcessResponse]:
    items = await service.list_processes(tenant.organization_id, limit=limit, offset=offset)
    return [
        RuntimeProcessResponse(
            process_id=UUID(p.process_id),
            organization_id=p.organization_id,
            runtime_event_id=UUID(p.runtime_event_id),
            process_name=p.process_name,
            executable_path=p.executable_path,
            pid=p.pid,
            parent_pid=p.parent_pid,
            command_line=p.command_line,
            user_name=p.user_name,
            created_at=p.created_at.isoformat(),
        )
        for p in items
    ]


@router.get(
    "/runtime/network-connections",
    response_model=list[RuntimeNetworkConnectionResponse],
)
async def list_runtime_network_connections(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RuntimeQueryService = Depends(get_runtime_query_service),
) -> list[RuntimeNetworkConnectionResponse]:
    items = await service.list_network_connections(
        tenant.organization_id, limit=limit, offset=offset
    )
    return [
        RuntimeNetworkConnectionResponse(
            connection_id=UUID(c.connection_id),
            organization_id=c.organization_id,
            runtime_event_id=UUID(c.runtime_event_id),
            direction=c.direction,
            protocol=c.protocol,
            local_address=c.local_address,
            local_port=c.local_port,
            remote_address=c.remote_address,
            remote_port=c.remote_port,
            created_at=c.created_at.isoformat(),
        )
        for c in items
    ]


@router.get("/runtime/summary", response_model=RuntimeSummaryResponse)
async def runtime_summary(
    since: datetime | None = Query(None),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RuntimeQueryService = Depends(get_runtime_query_service),
) -> RuntimeSummaryResponse:
    summary = await service.summary(tenant.organization_id, since=since)
    return RuntimeSummaryResponse(
        organization_id=summary.organization_id,
        total_events=summary.total_events,
        by_event_type=dict(summary.by_event_type),
        by_source=dict(summary.by_source),
        process_count=summary.process_count,
        connection_count=summary.connection_count,
    )
