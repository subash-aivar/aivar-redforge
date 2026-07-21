"""REST API for exposure_reporting Phase 5."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from exposure_reporting.api.dependencies import get_actor_roles, get_container, get_tenant_id
from exposure_reporting.api.schemas.reporting_schemas import (
    CreateBusinessImpactMappingRequest,
    DeliverReportRequest,
    GenerateReportRequest,
    UpdateBusinessImpactMappingRequest,
)
from exposure_reporting.application.commands.reporting_commands import (
    CreateBusinessImpactMappingCommand,
    DeliverExposureReportCommand,
    GenerateExposureReportCommand,
    UpdateBusinessImpactMappingCommand,
)
from exposure_reporting.application.exceptions import (
    ApplicationConflictError,
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from exposure_reporting.domain.exceptions.domain_exceptions import (
    ExposureReportingDomainError,
)
from exposure_reporting.infrastructure.container import ExposureReportingContainer

router = APIRouter(prefix="/exposure-reporting", tags=["exposure-reporting"])


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ApplicationConflictError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (ApplicationValidationError, ExposureReportingDomainError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Internal error")


@router.post("/reports")
async def generate_report(
    body: GenerateReportRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.report_service.generate(
            GenerateExposureReportCommand(
                tenant_id=tenant_id,
                report_type=body.report_type,
                generated_by=body.generated_by,
                time_range_start=body.time_range_start,
                time_range_end=body.time_range_end,
                actor_roles=roles,
            )
        )
        container.metrics.reports_generated += 1
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports/{report_id}")
async def get_report(
    report_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.report_service.get(tenant_id, report_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports")
async def list_reports(
    report_type: str | None = Query(default=None),
    from_dt: datetime | None = Query(default=None, alias="from"),
    to_dt: datetime | None = Query(default=None, alias="to"),
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.report_service.list_reports(
            tenant_id, roles, report_type=report_type, from_dt=from_dt, to_dt=to_dt
        )
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/reports/{report_id}/deliver")
async def deliver_report(
    report_id: UUID,
    body: DeliverReportRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.report_service.deliver(
            DeliverExposureReportCommand(
                tenant_id=tenant_id,
                report_id=report_id,
                delivery_channel=body.delivery_channel,
                actor_roles=roles,
            )
        )
        container.metrics.reports_delivered += 1
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports/{report_id}/export")
async def export_report(
    report_id: UUID,
    format: str = Query(default="json"),
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> Response:
    try:
        if format == "markdown":
            body = await container.export_service.export_markdown(tenant_id, report_id, roles)
            return Response(content=body, media_type="text/markdown")
        body = await container.export_service.export_json(tenant_id, report_id, roles)
        return Response(content=body, media_type="application/json")
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/business-impact-mappings")
async def create_mapping(
    body: CreateBusinessImpactMappingRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.mapping_service.create(
            CreateBusinessImpactMappingCommand(
                tenant_id=tenant_id,
                asset_ref_id=body.asset_ref_id,
                criticality=body.criticality,
                impact_domain=body.impact_domain,
                authored_by=body.authored_by,
                business_process_ref=body.business_process_ref,
                business_unit_ref=body.business_unit_ref,
                financial_impact_estimate=body.financial_impact_estimate,
                regulatory_scope=tuple(body.regulatory_scope),
                actor_roles=roles,
            )
        )
        container.metrics.mappings_created += 1
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.put("/business-impact-mappings/assets/{asset_ref_id}")
async def update_mapping(
    asset_ref_id: UUID,
    body: UpdateBusinessImpactMappingRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.mapping_service.update(
            UpdateBusinessImpactMappingCommand(
                tenant_id=tenant_id,
                asset_ref_id=asset_ref_id,
                criticality=body.criticality,
                impact_domain=body.impact_domain,
                authored_by=body.authored_by,
                business_process_ref=body.business_process_ref,
                business_unit_ref=body.business_unit_ref,
                financial_impact_estimate=body.financial_impact_estimate,
                regulatory_scope=(
                    tuple(body.regulatory_scope) if body.regulatory_scope is not None else None
                ),
                actor_roles=roles,
            )
        )
        container.metrics.mappings_updated += 1
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/business-impact-mappings/assets/{asset_ref_id}")
async def get_mapping(
    asset_ref_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.mapping_service.get_by_asset(tenant_id, asset_ref_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/business-impact-mappings")
async def list_mappings(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [asdict(m) for m in await container.mapping_service.list_mappings(tenant_id, roles)]
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/dashboard")
async def get_dashboard(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.dashboard.get_dashboard(tenant_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/trends")
async def get_trends(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.dashboard.get_trends(tenant_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/kpis")
async def get_kpis(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.dashboard.get_kpis(tenant_id, roles)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/admin/projections/rebuild")
async def rebuild_projections(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        result = await container.projections.rebuild_read_models(tenant_id, roles)
        container.metrics.projection_rebuilds += 1
        return result
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/admin/projections/repair")
async def repair_projections(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.projections.repair_projections(tenant_id, roles)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/admin/graph/sync")
async def sync_graph(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.projections.sync_graph_from_reports(tenant_id, roles)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/metrics")
async def metrics(
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    return container.metrics.snapshot()


@router.get("/health")
async def health(
    container: ExposureReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "exposure_reporting",
        "phase": 5,
        "graph_enabled": container.settings.enable_graph_projection,
        "workers_enabled": container.settings.enable_background_workers,
    }
