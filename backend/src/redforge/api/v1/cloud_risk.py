"""M26 Phase 7 Cloud Risk Correlation Engine APIs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_risk_calculation_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.risk.dtos import CalculateRiskCommand
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.risk.calculation_service import (
        RiskCalculationService,
    )

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class CalculateRiskRequest(BaseModel):
    asset_id: UUID | None = None
    account_id: UUID | None = None
    organization_wide: bool = False
    incremental: bool = False
    asset_ids: list[UUID] = Field(default_factory=list)


class RiskAssessmentResponse(BaseModel):
    assessment_id: str
    organization_id: str
    scope: str
    target_id: str
    status: str
    assets_evaluated: int
    risks_created: int
    risks_updated: int
    calculation_version: str
    diagnostics: dict[str, Any] = Field(default_factory=dict)


class RiskScoreResponse(BaseModel):
    risk_id: UUID
    organization_id: str
    cloud_asset_id: UUID
    overall_score: float
    threat_intel_score: float
    compliance_score: float
    identity_score: float
    exposure_score: float
    business_criticality_score: float
    attack_path_score: float
    cspm_score: float
    kubernetes_score: float
    runtime_score: float
    confidence: str
    trend: str
    state: str
    calculation_version: str
    computed_at: str
    valid_until: str
    score_components: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class RiskSummaryResponse(BaseModel):
    organization_id: str
    total_scores: int
    average_score: float
    critical_count: int
    high_count: int
    by_state: dict[str, int] = Field(default_factory=dict)
    by_trend: dict[str, int] = Field(default_factory=dict)


class RiskFactorResponse(BaseModel):
    factor_id: UUID
    organization_id: str
    cloud_asset_id: UUID
    category: str
    source: str
    title: str
    description: str
    score: float
    severity: str
    confidence: str


def _score_response(dto: Any) -> RiskScoreResponse:
    return RiskScoreResponse(
        risk_id=UUID(dto.risk_id),
        organization_id=dto.organization_id,
        cloud_asset_id=UUID(dto.cloud_asset_id),
        overall_score=dto.overall_score,
        threat_intel_score=dto.threat_intel_score,
        compliance_score=dto.compliance_score,
        identity_score=dto.identity_score,
        exposure_score=dto.exposure_score,
        business_criticality_score=dto.business_criticality_score,
        attack_path_score=dto.attack_path_score,
        cspm_score=dto.cspm_score,
        kubernetes_score=dto.kubernetes_score,
        runtime_score=dto.runtime_score,
        confidence=dto.confidence,
        trend=dto.trend,
        state=dto.state,
        calculation_version=dto.calculation_version,
        computed_at=dto.computed_at.isoformat(),
        valid_until=dto.valid_until.isoformat(),
        score_components=list(dto.score_components),
        evidence=list(dto.evidence),
    )


@router.post(
    "/risk/calculate",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def calculate_risk(
    body: CalculateRiskRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> RiskAssessmentResponse:
    result = await service.calculate(
        CalculateRiskCommand(
            organization_id=tenant.organization_id,
            asset_id=body.asset_id,
            account_id=body.account_id,
            organization_wide=body.organization_wide,
            incremental=body.incremental,
            asset_ids=tuple(body.asset_ids),
        )
    )
    return RiskAssessmentResponse(
        assessment_id=result.assessment_id,
        organization_id=result.organization_id,
        scope=result.scope,
        target_id=result.target_id,
        status=result.status,
        assets_evaluated=result.assets_evaluated,
        risks_created=result.risks_created,
        risks_updated=result.risks_updated,
        calculation_version=result.calculation_version,
        diagnostics=dict(result.diagnostics),
    )


@router.post(
    "/risk/recalculate-organization",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def recalculate_organization(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> RiskAssessmentResponse:
    result = await service.recalculate_organization(tenant.organization_id)
    return RiskAssessmentResponse(
        assessment_id=result.assessment_id,
        organization_id=result.organization_id,
        scope=result.scope,
        target_id=result.target_id,
        status=result.status,
        assets_evaluated=result.assets_evaluated,
        risks_created=result.risks_created,
        risks_updated=result.risks_updated,
        calculation_version=result.calculation_version,
        diagnostics=dict(result.diagnostics),
    )


@router.get("/risk/scores", response_model=list[RiskScoreResponse])
async def list_risk_scores(
    min_score: float | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> list[RiskScoreResponse]:
    items = await service.list_scores(
        tenant.organization_id, min_score=min_score, limit=limit, offset=offset
    )
    return [_score_response(item) for item in items]


@router.get("/risk/scores/{risk_id}", response_model=RiskScoreResponse)
async def get_risk_score(
    risk_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> RiskScoreResponse:
    dto = await service.get_score(tenant.organization_id, risk_id=risk_id)
    return _score_response(dto)


@router.get("/risk/by-asset/{asset_id}", response_model=RiskScoreResponse)
async def get_risk_by_asset(
    asset_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> RiskScoreResponse:
    dto = await service.get_score(tenant.organization_id, asset_id=asset_id)
    return _score_response(dto)


@router.get("/risk/summary", response_model=RiskSummaryResponse)
async def risk_summary(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> RiskSummaryResponse:
    dto = await service.summary(tenant.organization_id)
    return RiskSummaryResponse(
        organization_id=dto.organization_id,
        total_scores=dto.total_scores,
        average_score=dto.average_score,
        critical_count=dto.critical_count,
        high_count=dto.high_count,
        by_state=dict(dto.by_state),
        by_trend=dict(dto.by_trend),
    )


@router.get("/risk/history")
async def risk_history(
    asset_id: UUID = Query(...),
    limit: int = Query(50, ge=1, le=500),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> list[dict[str, Any]]:
    return await service.history(tenant.organization_id, asset_id, limit=limit)


@router.get("/risk/top", response_model=list[RiskScoreResponse])
async def risk_top(
    limit: int = Query(10, ge=1, le=100),
    threshold: float = Query(0.0, ge=0.0, le=10.0),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> list[RiskScoreResponse]:
    items = await service.top(
        tenant.organization_id, limit=limit, threshold=threshold
    )
    return [_score_response(item) for item in items]


@router.get("/risk/factors", response_model=list[RiskFactorResponse])
async def risk_factors(
    asset_id: UUID = Query(...),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: RiskCalculationService = Depends(get_risk_calculation_service),
) -> list[RiskFactorResponse]:
    items = await service.list_factors(tenant.organization_id, asset_id)
    return [
        RiskFactorResponse(
            factor_id=UUID(f.factor_id),
            organization_id=f.organization_id,
            cloud_asset_id=UUID(f.cloud_asset_id),
            category=f.category,
            source=f.source,
            title=f.title,
            description=f.description,
            score=f.score,
            severity=f.severity,
            confidence=f.confidence,
        )
        for f in items
    ]
