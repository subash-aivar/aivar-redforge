from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from regulatory_notification.api.dependencies import get_container, roles_header, tenant_id_header
from regulatory_notification.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from regulatory_notification.domain.exceptions.domain_exceptions import RegulatoryDomainError
from regulatory_notification.domain.value_objects.identifiers import TenantId
from regulatory_notification.infrastructure.container import RegulatoryNotificationContainer

router = APIRouter(prefix="/regulatory-notification", tags=["regulatory-notification"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(403, str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(404, str(exc))
    if isinstance(exc, RegulatoryDomainError):
        return HTTPException(409, str(exc))
    return HTTPException(400, str(exc))


class StartBody(BaseModel):
    incident_id: str
    regimes: list[str] | None = None


class DraftBody(BaseModel):
    content: str
    actor: str = "api"


class SubmitBody(BaseModel):
    actor: str
    submission_method: str
    reference_number: str


class JurisBody(BaseModel):
    jurisdictions: list[str]


@router.get("/health")
async def health(
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "regulatory_notification",
        "phase": 5,
        "dead_letter_count": len(container.deadline_worker.dead_letters),
    }


@router.post("/jurisdictions")
async def configure(
    body: JurisBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.configure_jurisdictions(
            tenant_id, set(body.jurisdictions), roles
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/clocks")
async def start_clocks(
    body: StartBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return await container.app.start_clocks(tenant_id, body.incident_id, body.regimes, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{notification_id}/drafts")
async def create_draft(
    notification_id: UUID,
    body: DraftBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.create_draft(
            tenant_id, notification_id, body.content, body.actor, roles
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{notification_id}/drafts/revise")
async def revise(
    notification_id: UUID,
    body: DraftBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.revise_draft(
            tenant_id, notification_id, body.content, body.actor, roles
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{notification_id}/drafts/finalize")
async def finalize(
    notification_id: UUID,
    body: DraftBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.finalize_draft(tenant_id, notification_id, body.actor, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{notification_id}/submit")
async def submit(
    notification_id: UUID,
    body: SubmitBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.submit(
            tenant_id,
            notification_id,
            body.actor,
            body.submission_method,
            body.reference_number,
            roles,
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/incident/{incident_id}")
async def list_incident(
    incident_id: str,
    tenant_id: TenantId = Depends(tenant_id_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    return await container.app.list_for_incident(tenant_id, incident_id)


@router.get("/deadlines/dashboard")
async def deadlines(
    tenant_id: TenantId = Depends(tenant_id_header),
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    return await container.app.deadline_dashboard(tenant_id)


@router.post("/admin/deadline-tick")
async def deadline_tick(
    container: RegulatoryNotificationContainer = Depends(get_container),
) -> dict[str, Any]:
    return await container.deadline_worker.reconstitute_and_tick()
