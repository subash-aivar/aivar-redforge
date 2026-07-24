from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from lessons_learned.api.dependencies import get_container, roles_header, tenant_id_header
from lessons_learned.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from lessons_learned.domain.value_objects.identifiers import TenantId
from lessons_learned.infrastructure.container import LessonsLearnedContainer

router = APIRouter(prefix="/lessons-learned", tags=["lessons-learned"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(403, str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(404, str(exc))
    return HTTPException(400, str(exc))


class CreateBody(BaseModel):
    incident_id: str
    technique_ids: list[str] = []


class LessonBody(BaseModel):
    category: str
    description: str
    impact_summary: str


class ActionBody(BaseModel):
    title: str
    description: str
    owner: str
    priority: str


class ActorBody(BaseModel):
    actor: str = "api"


class ReportBody(BaseModel):
    format: str


class ExportBody(BaseModel):
    destination: str


@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "context": "lessons_learned", "phase": 5}


@router.post("")
async def create(
    body: CreateBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.create_for_incident(
            tenant_id, body.incident_id, roles, body.technique_ids
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{ll_id}/lessons")
async def add_lesson(
    ll_id: UUID,
    body: LessonBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.add_lesson(
            tenant_id, ll_id, body.category, body.description, body.impact_summary, roles
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{ll_id}/actions")
async def add_action(
    ll_id: UUID,
    body: ActionBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.add_action(
            tenant_id, ll_id, body.title, body.description, body.owner, body.priority, roles
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{ll_id}/review")
async def review(
    ll_id: UUID,
    body: ActorBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.review(tenant_id, ll_id, body.actor, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{ll_id}/finalize")
async def finalize(
    ll_id: UUID,
    body: ActorBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.finalize(tenant_id, ll_id, body.actor, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{ll_id}/reports")
async def report(
    ll_id: UUID,
    body: ReportBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.generate_report(tenant_id, ll_id, body.format, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/reports/{report_id}/export")
async def export(
    report_id: UUID,
    body: ExportBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.export_report(tenant_id, report_id, body.destination, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/incident/{incident_id}")
async def get(
    incident_id: str,
    tenant_id: TenantId = Depends(tenant_id_header),
    container: LessonsLearnedContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.get(tenant_id, incident_id)
    except Exception as exc:
        raise _map(exc) from exc
