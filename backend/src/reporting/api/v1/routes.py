"""REST API for reporting Phase 2 — prefix /reporting."""

from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from reporting.api.dependencies import get_actor_roles, get_container, get_tenant_id
from reporting.api.schemas.reporting_schemas import (
    BIExportRequestBody,
    CreateScheduledReportRequest,
    ExportReportRequest,
    GenerateReportOnDemandRequest,
)
from reporting.application.commands.reporting_commands import (
    CreateScheduledReportCommand,
    GenerateReportOnDemandCommand,
)
from reporting.application.exceptions import (
    ApplicationConflictError,
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationRateLimitedError,
    ApplicationValidationError,
)
from reporting.domain.exceptions.domain_exceptions import ReportingDomainError
from reporting.domain.value_objects.identifiers import TenantId
from reporting.infrastructure.container import ReportingContainer

router = APIRouter(prefix="/reporting", tags=["reporting"])


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ApplicationConflictError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ApplicationRateLimitedError):
        return HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )
    if isinstance(exc, (ApplicationValidationError, ReportingDomainError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Internal error")


@router.post("/schedules")
async def create_scheduled_report(
    body: CreateScheduledReportRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.create_scheduled_report(
            CreateScheduledReportCommand(
                tenant_id=tenant_id,
                template_id=body.template_id,
                schedule=body.schedule,
                created_by=body.created_by,
                parameters=dict(body.parameters),
                recipients=tuple(body.recipients),
                cadence_minutes=body.cadence_minutes,
                actor_roles=roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/reports")
async def generate_report_on_demand(
    body: GenerateReportOnDemandRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.generate_on_demand(
            GenerateReportOnDemandCommand(
                tenant_id=tenant_id,
                template_id=body.template_id,
                generated_by=body.generated_by,
                parameters=dict(body.parameters),
                actor_roles=roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports/{instance_id}")
async def get_report_instance(
    instance_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_instance(tenant_id, instance_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports")
async def list_report_instances(
    template_id: UUID | None = Query(default=None),
    from_dt: datetime | None = Query(default=None, alias="from"),
    to_dt: datetime | None = Query(default=None, alias="to"),
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ReportingContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.list_instances(
            tenant_id,
            roles,
            template_id=template_id,
            from_dt=from_dt,
            to_dt=to_dt,
        )
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/templates")
async def list_templates(
    container: ReportingContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    store = getattr(container.template_repo, "_by_id", {})
    return [
        {
            "template_id": str(t.template_id),
            "report_type": t.report_type.value,
            "name": t.name,
            "sections": list(t.sections),
        }
        for t in store.values()
    ]


@router.post("/reports/{instance_id}/export")
async def export_report(
    instance_id: UUID,
    body: ExportReportRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        result = await container.app.export_instance(tenant_id, instance_id, body.format, roles)
        raw = result.pop("bytes")
        assert isinstance(raw, (bytes, bytearray))
        result["content_base64"] = base64.b64encode(bytes(raw)).decode("ascii")
        return result
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/bi-export")
async def bi_export(
    body: BIExportRequestBody,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.bi_export_page(
            tenant_id,
            body.dataset_ref,
            roles,
            page=body.page,
            page_size=body.page_size,
            actor=body.actor,
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/delivery-audit")
async def delivery_audit(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ReportingContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    from reporting.application._auth import require_at_least
    from reporting.domain.value_objects.enums import AnalyticsRole

    try:
        require_at_least(roles, AnalyticsRole.ANALYST)
        return container.delivery_audit.list_for_tenant(tenant_id)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/health")
async def health(
    container: ReportingContainer = Depends(get_container),
) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "reporting",
        "phase": 5,
        "adr": "ADR-M33-001",
        "template_count": len(getattr(container.template_repo, "_by_id", {})),
        "delivery_audit_count": len(container.delivery_audit.rows),
    }
