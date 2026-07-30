"""Risk correlation + cross-cutting orchestration API routers (M48F).

Bounded strictly by `RiskCorrelationApplicationService`'s existing
surface (form_correlation_sets, evaluate_escalation,
evaluate_acceptance_expiry) plus `RiskQueryService.get_correlation_set`
for the single-correlation read. No new business capability is added.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission
from risk_engine.api.dependencies import CorrelationServiceDep, QueryServiceDep, TenantIdDep
from risk_engine.api.schemas.risk_schemas import (
    FormRiskCorrelationSetsRequest,
    RiskCorrelationFormationResponse,
    RiskCorrelationResponse,
)
from risk_engine.api.v1.risk_profiles import _signal_reference
from risk_engine.application.commands.risk_correlation_commands import (
    FormRiskCorrelationSetsCommand,
)
from risk_engine.application.queries.risk_profile_queries import GetRiskCorrelationSetQuery
from risk_engine.domain.value_objects.identifiers import CorrelationSetId

risk_correlations_router = APIRouter()


@risk_correlations_router.post(
    "/form",
    response_model=RiskCorrelationFormationResponse,
    summary="Form risk correlation sets from a batch of risk signals",
)
async def form_risk_correlation_sets(
    body: FormRiskCorrelationSetsRequest,
    tenant_id: TenantIdDep,
    svc: CorrelationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskCorrelationFormationResponse:
    try:
        signal_references = tuple(
            _signal_reference(ref, tenant_id) for ref in body.signal_references
        )
    except HTTPException:
        raise
    result = await svc.form_correlation_sets(
        FormRiskCorrelationSetsCommand(
            tenant_id=tenant_id,
            signal_references=signal_references,
            correlation_window=timedelta(seconds=body.correlation_window_seconds),
        )
    )
    return RiskCorrelationFormationResponse.model_validate(asdict(result))


@risk_correlations_router.get(
    "/{correlation_set_id}",
    response_model=RiskCorrelationResponse,
    summary="Get a risk correlation set",
)
async def get_risk_correlation_set(
    correlation_set_id: UUID,
    tenant_id: TenantIdDep,
    svc: QueryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> RiskCorrelationResponse:
    dto = await svc.get_correlation_set(
        GetRiskCorrelationSetQuery(
            tenant_id=tenant_id,
            correlation_set_id=CorrelationSetId(correlation_set_id),
        )
    )
    if dto is None:
        raise HTTPException(status_code=404, detail=f"No risk correlation set {correlation_set_id}")
    return RiskCorrelationResponse.model_validate(asdict(dto))
