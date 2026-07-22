from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from autonomous_intelligence.api.dependencies import get_container, roles_header, tenant_id_header
from autonomous_intelligence.application.commands.intelligence_commands import (
    ApproveSuggestion,
    CreateIntelligenceSuggestion,
    DeployOptimizationModel,
    RejectSuggestion,
    TrainOptimizationModel,
)
from autonomous_intelligence.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AutonomousIntelligenceDomainError,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer

router = APIRouter(prefix="/autonomous-intelligence", tags=["autonomous-intelligence"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, AutonomousIntelligenceDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class CreateSuggestionBody(BaseModel):
    target_context: str
    target_type: str
    proposed_change_payload: dict[str, object] = Field(default_factory=dict)
    model_id: str = "model-default"
    model_version: int = 1
    confidence_score: float
    supporting_signal_refs: list[str] = Field(default_factory=list)
    rationale_summary: str
    target_id: UUID | None = None


class ReviewBody(BaseModel):
    actor: str
    reason: str | None = None


class TrainBody(BaseModel):
    target_type: str
    model_id: str
    model_version: int = 1


class DeployBody(BaseModel):
    conformity_assessment_ref: str
    accuracy_metrics: dict[str, float]


@router.get("/health")
async def health(
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "autonomous_intelligence",
        "metrics": container.metrics.snapshot(),
        "audit_count": len(container.audit_log),
    }


@router.get("/suggestions")
async def list_queue(
    target_type: str | None = None,
    limit: int = 50,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.get_queue(tenant_id, roles, target_type, limit)
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/suggestions", status_code=201)
async def create_suggestion(
    body: CreateSuggestionBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.create_suggestion(
            CreateIntelligenceSuggestion(
                tenant_id,
                body.target_context,
                body.target_id,
                body.target_type,
                body.proposed_change_payload,
                body.model_id,
                body.model_version,
                body.confidence_score,
                tuple(body.supporting_signal_refs),
                body.rationale_summary,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/suggestions/{suggestion_id}")
async def get_suggestion(
    suggestion_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_suggestion(tenant_id, suggestion_id, roles))
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/suggestions/{suggestion_id}/approve")
async def approve(
    suggestion_id: UUID,
    body: ReviewBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.approve(
            ApproveSuggestion(tenant_id, suggestion_id, body.actor, roles)
        )
        for event in list(container.event_sink):
            container.graph_worker.project(event)
            container.analytics.project(event)
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/suggestions/{suggestion_id}/reject")
async def reject(
    suggestion_id: UUID,
    body: ReviewBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.reject(
            RejectSuggestion(tenant_id, suggestion_id, body.actor, body.reason or "rejected", roles)
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/policy")
async def get_policy(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_policy(tenant_id, roles))
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/acceptance-rate")
async def acceptance_rate(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [asdict(r) for r in await container.app.get_acceptance_rate(tenant_id, roles)]
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/models/accuracy")
async def model_accuracy(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [asdict(r) for r in await container.app.get_model_accuracy(tenant_id, roles)]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/models/train", status_code=201)
async def train(
    body: TrainBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.train_model(
            TrainOptimizationModel(
                tenant_id, body.target_type, body.model_id, body.model_version, roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/models/{model_id}/deploy")
async def deploy(
    model_id: str,
    body: DeployBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.deploy_model(
            DeployOptimizationModel(
                tenant_id, model_id, body.conformity_assessment_ref, body.accuracy_metrics, roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/llm-audit")
async def llm_audit(
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    return list(container.audit_log)
