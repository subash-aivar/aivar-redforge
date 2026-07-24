"""REST API for remediation_impact Phase 4."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from remediation_impact.api.dependencies import get_actor_roles, get_container, get_tenant_id
from remediation_impact.api.schemas.plan_schemas import CommitPlanRequest, GeneratePlanRequest
from remediation_impact.application.commands.plan_commands import (
    CommitExposureReductionPlanCommand,
    GenerateExposureReductionPlanCommand,
    RemediationCandidateInput,
)
from remediation_impact.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from remediation_impact.domain.exceptions.domain_exceptions import (
    RemediationImpactDomainError,
)
from remediation_impact.domain.value_objects.identifiers import TenantId
from remediation_impact.infrastructure.container import RemediationImpactContainer

router = APIRouter(prefix="/remediation-impact", tags=["remediation-impact"])


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ApplicationValidationError, RemediationImpactDomainError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Internal error")


@router.post("/plans")
async def generate_plan(
    body: GeneratePlanRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: RemediationImpactContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.plan_service.generate(
            GenerateExposureReductionPlanCommand(
                tenant_id=tenant_id,
                candidate_remediations=tuple(
                    RemediationCandidateInput(
                        remediation_id=c.remediation_id,
                        affected_asset_refs=tuple(c.affected_asset_refs),
                        estimated_amplifier_removals=tuple(c.estimated_amplifier_removals),
                        estimated_base_reduction=c.estimated_base_reduction,
                    )
                    for c in body.candidate_remediations
                ),
                plan_budget=body.plan_budget,
                top_k=body.top_k,
                sample_size=body.sample_size,
                current_exposure_scores=body.current_exposure_scores,
                score_input_version=body.score_input_version,
                actor_roles=roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/plans/{plan_id}/commit")
async def commit_plan(
    plan_id: UUID,
    body: CommitPlanRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: RemediationImpactContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.plan_service.commit(
            CommitExposureReductionPlanCommand(
                tenant_id=tenant_id,
                plan_id=plan_id,
                committed_by=body.committed_by,
                actor_roles=roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/plans/{plan_id}")
async def get_plan(
    plan_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: RemediationImpactContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.plan_service.get(tenant_id, plan_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/plans")
async def list_plans(
    status: str | None = Query(default=None),
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: RemediationImpactContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.plan_service.list_plans(tenant_id, roles, status_filter=status)
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "context": "remediation_impact", "phase": 4}
