"""Projection / correlation / replay API routes (M29 Phase 6)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from execution.api.dependencies import (
    ProjectionServiceDep,
    TenantIdDep,
)
from execution.api.schemas.execution_schemas import (
    CorrelateDetectionFindingRequest,
    DetectionCoverageResponse,
    ProjectionReplayRequest,
    ReplaySimulationRequest,
)
from execution.application.services.detection_correlation_service import (
    CorrelateDetectionFinding,
)
from execution.application.services.replay_application_service import (
    ReplayAttackActionExecution,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

projections_router = APIRouter()


@projections_router.get(
    "/detection-coverage",
    response_model=DetectionCoverageResponse,
)
async def get_detection_coverage(
    service: ProjectionServiceDep,
    tenant_id: TenantIdDep,
    view_key: str = Query(default="default"),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> DetectionCoverageResponse:
    payload = await service.get_detection_coverage(tenant_id, view_key)
    if payload is None:
        return DetectionCoverageResponse(
            tenant_id=str(tenant_id),
            view_key=view_key,
            total_actions=0,
            detected_count=0,
            coverage_pct=0.0,
        )
    return DetectionCoverageResponse(**payload)


@projections_router.post("/replay-simulation")
async def replay_simulation(
    body: ReplaySimulationRequest,
    service: ProjectionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ANALYST)),
) -> dict[str, Any]:
    report = await service.replay_attack_action_execution(
        ReplayAttackActionExecution(
            tenant_id=tenant_id,
            journal_id=body.journal_id,
            engagement_id=body.engagement_id,
        )
    )
    return report.to_dict()


@projections_router.post("/projection-replay")
async def projection_replay(
    body: ProjectionReplayRequest,
    service: ProjectionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> dict[str, Any]:
    org = body.tenant_id or tenant_id
    return await service.replay(tenant_id=org, from_position=body.from_position)


@projections_router.post("/correlate-detection")
async def correlate_detection(
    body: CorrelateDetectionFindingRequest,
    service: ProjectionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ANALYST)),
) -> dict[str, Any]:
    if service.correlation is None:
        return {"error": "correlation_not_configured"}
    result = await service.correlation.correlate_command(
        CorrelateDetectionFinding(
            tenant_id=str(tenant_id),
            action_id=str(body.action_id),
            finding_id=str(body.finding_id),
            rule_id=body.rule_id,
            detected_at=body.detected_at,
        )
    )
    return result.to_dict()


@projections_router.get("/health")
async def projection_health(
    service: ProjectionServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> dict[str, Any]:
    return service.projection_status()
