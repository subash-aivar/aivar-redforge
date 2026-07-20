"""Telemetry source API routers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response, status

from detection.api.dependencies import TelemetryServiceDep, TenantIdDep
from detection.api.schemas.telemetry_schemas import (
    ListTelemetrySourcesResponse,
    RegisterTelemetrySourceRequest,
    TelemetrySourceResponse,
    UpdateTelemetrySourceRequest,
    ValidateSourceResponse,
)
from detection.application.commands.telemetry_commands import (
    DeactivateTelemetrySource,
    RegisterTelemetrySource,
    UpdateTelemetrySource,
    UpdateTelemetrySourceHealth,
)
from detection.application.dtos.telemetry_dtos import TelemetrySourceDTO
from detection.application.queries.telemetry_queries import (
    GetTelemetrySource,
    ListTelemetrySources,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

telemetry_router = APIRouter()


def _to_response(dto: TelemetrySourceDTO) -> TelemetrySourceResponse:
    from dataclasses import asdict

    return TelemetrySourceResponse.model_validate(asdict(dto))


@telemetry_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=TelemetrySourceResponse,
)
async def register_telemetry_source(
    body: RegisterTelemetrySourceRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: TelemetryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> TelemetrySourceResponse:
    dto = await svc.register_telemetry_source(
        RegisterTelemetrySource(
            tenant_id=tenant_id,
            name=body.name,
            source_type=body.source_type,
            trust_level=body.trust_level,
            schema_version=body.schema_version,
            fields=[f.model_dump() for f in body.fields],
            adapter_key=body.adapter_key,
            tenant_scope_assertion=body.tenant_scope_assertion,
            latency_expected_seconds=body.latency_expected_seconds,
            retention_seconds=body.retention_seconds,
            description=body.description,
            endpoint_url=body.endpoint_url,
            options=body.options,
            latency_max_seconds=body.latency_max_seconds,
        )
    )
    response.headers["Location"] = f"/api/v1/telemetry-sources/{dto.id}"
    return _to_response(dto)


@telemetry_router.get("", response_model=ListTelemetrySourcesResponse)
async def list_telemetry_sources(
    tenant_id: TenantIdDep,
    svc: TelemetryServiceDep,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    active_only: bool = Query(default=False),
    source_type: str | None = Query(default=None),
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> ListTelemetrySourcesResponse:
    page = await svc.list_telemetry_sources(
        ListTelemetrySources(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            active_only=active_only,
            source_type=source_type,
        )
    )
    return ListTelemetrySourcesResponse(
        items=[_to_response(i) for i in page.items],
        limit=page.limit,
        offset=page.offset,
    )


@telemetry_router.get("/{source_id}", response_model=TelemetrySourceResponse)
async def get_telemetry_source(
    source_id: str,
    tenant_id: TenantIdDep,
    svc: TelemetryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> TelemetrySourceResponse:
    from uuid import UUID

    dto = await svc.get_telemetry_source(
        GetTelemetrySource(tenant_id=tenant_id, source_id=UUID(source_id))
    )
    return _to_response(dto)


@telemetry_router.patch("/{source_id}", response_model=TelemetrySourceResponse)
async def patch_telemetry_source(
    source_id: str,
    body: UpdateTelemetrySourceRequest,
    tenant_id: TenantIdDep,
    svc: TelemetryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> TelemetrySourceResponse:
    from uuid import UUID

    sid = UUID(source_id)
    if body.deactivate_reason:
        dto = await svc.deactivate_telemetry_source(
            DeactivateTelemetrySource(
                tenant_id=tenant_id,
                source_id=sid,
                reason=body.deactivate_reason,
            )
        )
        return _to_response(dto)
    if body.health_status:
        dto = await svc.update_telemetry_source_health(
            UpdateTelemetrySourceHealth(
                tenant_id=tenant_id,
                source_id=sid,
                status=body.health_status,
                detail=body.health_detail,
                success=body.health_success,
            )
        )
        return _to_response(dto)
    dto = await svc.update_telemetry_source(
        UpdateTelemetrySource(
            tenant_id=tenant_id,
            source_id=sid,
            description=body.description,
            trust_level=body.trust_level,
            schema_version=body.schema_version,
            fields=[f.model_dump() for f in body.fields] if body.fields else None,
            adapter_key=body.adapter_key,
            tenant_scope_assertion=body.tenant_scope_assertion,
            endpoint_url=body.endpoint_url,
            options=body.options,
            latency_expected_seconds=body.latency_expected_seconds,
            latency_max_seconds=body.latency_max_seconds,
            retention_seconds=body.retention_seconds,
        )
    )
    return _to_response(dto)


@telemetry_router.post("/{source_id}/validate", response_model=ValidateSourceResponse)
async def validate_telemetry_source(
    source_id: str,
    tenant_id: TenantIdDep,
    svc: TelemetryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> ValidateSourceResponse:
    from uuid import UUID

    dto = await svc.validate_telemetry_source(
        tenant_id=tenant_id,
        source_id=UUID(source_id),
    )
    return ValidateSourceResponse(
        source_id=dto.source_id,
        provider_registered=dto.provider_registered,
        schema_version_valid=dto.schema_version_valid,
        health_status=dto.health_status,
        capabilities=dto.capabilities,
        detail=dto.detail,
    )
