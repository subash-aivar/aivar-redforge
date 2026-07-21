from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from incident.api.dependencies import get_container, roles_header, tenant_id_header
from incident.application.commands.incident_commands import (
    AddRecoveryMilestoneCommand,
    AuthorizeContainmentCommand,
    ClassifyIncidentCommand,
    CloseIncidentCommand,
    CompleteContainmentCommand,
    CompleteRecoveryMilestoneCommand,
    DeclareIncidentCommand,
    FailContainmentCommand,
    LogCommunicationCommand,
    ReclassifyIncidentCommand,
    SubmitEradicationCommand,
    VerifyEradicationCommand,
)
from incident.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from incident.domain.exceptions.domain_exceptions import (
    AuthorizationDenied,
    ClosureRequirementsNotMet,
    DomainInvariantViolation,
    IncidentDomainError,
)
from incident.infrastructure.container import IncidentContainer

router = APIRouter(prefix="/incident", tags=["incident"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError | AuthorizationDenied):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ClosureRequirementsNotMet | DomainInvariantViolation | IncidentDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


@router.get("/health")
async def health(container: IncidentContainer = Depends(get_container)) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "incident",
        "phase": 5,
        "dead_letter_count": len(container.retry_worker.dead_letters),
        "metrics": container.metrics.snapshot(),
    }


@router.get("/dashboard/active")
async def dashboard(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        data = await container.app.dashboard(tenant_id, roles)
        data["incidents"] = [i.__dict__ for i in data["incidents"]]
        return data
    except Exception as exc:
        raise _map(exc) from exc


class DeclareBody(BaseModel):
    title: str
    description: str
    trigger_type: str
    severity: str
    actor: str = "api"
    source_finding_id: str | None = None
    investigation_id: str | None = None


class ClassifyBody(BaseModel):
    severity: str
    method: str
    actor: str = "api"


class ReclassifyBody(BaseModel):
    new_severity: str
    justification: str = Field(min_length=20)
    actor: str = "api"


class ContainmentBody(BaseModel):
    action_type: str
    description: str
    actor: str = "api"


class CompleteContainmentBody(BaseModel):
    evidence_ref: str
    actor: str = "api"


class FailContainmentBody(BaseModel):
    failure_reason: str
    actor: str = "api"


class EradicationBody(BaseModel):
    assertion: str
    evidence_ids: list[str]
    actor: str = "api"


class VerifyBody(BaseModel):
    actor: str = "api"


class CloseBody(BaseModel):
    resolution_type: str
    actor: str = "api"
    force: bool = False
    force_justification: str | None = None


class MilestoneBody(BaseModel):
    title: str
    description: str
    owner: str
    target_date: datetime
    actor: str = "api"


class CompleteMilestoneBody(BaseModel):
    notes: str
    actor: str = "api"
    mark_incident_recovered: bool = True


class CommBody(BaseModel):
    content: str
    communication_type: str
    recipient_summary: str
    actor: str = "api"


@router.post("")
async def declare(
    body: DeclareBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.declare(
            DeclareIncidentCommand(
                tenant_id,
                body.title,
                body.description,
                body.trigger_type,
                body.severity,
                body.actor,
                roles,
                body.source_finding_id,
                body.investigation_id,
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/classify")
async def classify(
    incident_id: UUID,
    body: ClassifyBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.classify(
            ClassifyIncidentCommand(
                tenant_id, incident_id, body.severity, body.method, body.actor, roles
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/reclassify")
async def reclassify(
    incident_id: UUID,
    body: ReclassifyBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.reclassify(
            ReclassifyIncidentCommand(
                tenant_id, incident_id, body.new_severity, body.justification, body.actor, roles
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/containment")
async def containment(
    incident_id: UUID,
    body: ContainmentBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.authorize_containment(
            AuthorizeContainmentCommand(
                tenant_id, incident_id, body.action_type, body.description, body.actor, roles
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/containment/{action_id}/complete")
async def complete_containment(
    action_id: UUID,
    body: CompleteContainmentBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.complete_containment(
            CompleteContainmentCommand(tenant_id, action_id, body.evidence_ref, body.actor, roles)
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/containment/{action_id}/fail")
async def fail_containment(
    action_id: UUID,
    body: FailContainmentBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.fail_containment(
            FailContainmentCommand(tenant_id, action_id, body.failure_reason, body.actor, roles)
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/eradication")
async def submit_eradication(
    incident_id: UUID,
    body: EradicationBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.submit_eradication(
            SubmitEradicationCommand(
                tenant_id, incident_id, body.assertion, tuple(body.evidence_ids), body.actor, roles
            )
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/eradication/verify")
async def verify_eradication(
    incident_id: UUID,
    body: VerifyBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.verify_eradication(
            VerifyEradicationCommand(tenant_id, incident_id, body.actor, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/close")
async def close_incident(
    incident_id: UUID,
    body: CloseBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.close(
            CloseIncidentCommand(
                tenant_id,
                incident_id,
                body.resolution_type,
                body.actor,
                roles,
                body.force,
                body.force_justification,
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/milestones")
async def add_milestone(
    incident_id: UUID,
    body: MilestoneBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.add_milestone(
            AddRecoveryMilestoneCommand(
                tenant_id,
                incident_id,
                body.title,
                body.description,
                body.owner,
                body.target_date
                if body.target_date.tzinfo
                else body.target_date.replace(tzinfo=UTC),
                body.actor,
                roles,
            )
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/milestones/{milestone_id}/complete")
async def complete_milestone(
    incident_id: UUID,
    milestone_id: UUID,
    body: CompleteMilestoneBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.complete_milestone(
            CompleteRecoveryMilestoneCommand(
                tenant_id,
                incident_id,
                milestone_id,
                body.notes,
                body.actor,
                roles,
                body.mark_incident_recovered,
            )
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{incident_id}/communications")
async def log_comm(
    incident_id: UUID,
    body: CommBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.log_communication(
            LogCommunicationCommand(
                tenant_id,
                incident_id,
                body.content,
                body.communication_type,
                body.recipient_summary,
                body.actor,
                roles,
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/{incident_id}")
async def get_incident(
    incident_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return (await container.app.get_incident(tenant_id, incident_id, roles)).__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.get("")
async def list_incidents(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [d.__dict__ for d in await container.app.list_incidents(tenant_id, roles)]
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/{incident_id}/communications")
async def get_comms(
    incident_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IncidentContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [d.__dict__ for d in await container.app.get_comm_log(tenant_id, incident_id, roles)]
    except Exception as exc:
        raise _map(exc) from exc
