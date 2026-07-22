from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from threat_hunt.api.dependencies import get_container, roles_header, tenant_id_header
from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.application.exceptions import ApplicationForbiddenError, ApplicationNotFoundError
from threat_hunt.domain.exceptions.domain_exceptions import ThreatHuntDomainError
from threat_hunt.infrastructure.container import ThreatHuntContainer

router = APIRouter(prefix="/threat-hunt", tags=["threat-hunt"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ThreatHuntDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class GenerateBody(BaseModel):
    anomaly_signal_ids: list[str]
    technique_ids: list[str] = Field(default_factory=lambda: ["T1059"])
    detection_logic_draft: str = "title: draft"
    confidence_score: float = 0.8
    detection_rule_format: str = "sigma"


class PromoteBody(BaseModel):
    promoted_by: str
    promoted_rule_version_id: UUID


class RejectBody(BaseModel):
    rejected_by: str
    rejection_reason: str


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "context": "threat_hunt"}


@router.get("/candidates")
async def list_candidates(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [asdict(r) for r in await container.app.queue(tenant_id, roles)]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/candidates", status_code=201)
async def generate(
    body: GenerateBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.generate(
            GenerateThreatHuntCandidate(
                tenant_id,
                tuple(body.anomaly_signal_ids),
                tuple(body.technique_ids),
                body.detection_logic_draft,
                body.confidence_score,
                roles,
                body.detection_rule_format,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/candidates/{candidate_id}/promote")
async def promote(
    candidate_id: UUID,
    body: PromoteBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.promote(
            PromoteThreatHuntCandidate(
                tenant_id,
                candidate_id,
                body.promoted_by,
                body.promoted_rule_version_id,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/candidates/{candidate_id}/reject")
async def reject(
    candidate_id: UUID,
    body: RejectBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.reject(
            RejectThreatHuntCandidate(
                tenant_id, candidate_id, body.rejected_by, body.rejection_reason, roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc
