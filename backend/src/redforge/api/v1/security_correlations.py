"""Security Correlation REST API — M9.

Tenant-scoped. Only `evaluate` performs a write (running the
server-controlled rule registry) — no endpoint accepts rule input,
sets evidence_state, or creates a correlation directly. Routers
contain no correlation logic; all of it lives in
`TenantSecurityCorrelationService`/`application/security_correlation/rules.py`.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_security_correlation_service
from redforge.api.security import TenantContext, require_permission
from redforge.core.exceptions import NotFoundError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.security_correlation.service import TenantSecurityCorrelationService

router = APIRouter(prefix="/security-correlations", tags=["security-correlations"])


class SecurityCorrelationResponse(BaseModel):
    id: str
    organization_id: str
    stable_rule_id: str
    rule_version: int
    evidence_state: str
    lifecycle: str
    title: str
    summary: str
    operator_action: str
    entity_ids: list[str]
    condition_ids: list[str]
    first_observed_at: str
    last_observed_at: str
    resolved_at: str | None


class CorrelationEvaluationResponse(BaseModel):
    rules_evaluated: int
    matched: int
    created: int
    updated: int
    resolved: int
    evaluated_at: str


@router.post("/evaluate", response_model=CorrelationEvaluationResponse)
async def evaluate_correlations(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantSecurityCorrelationService = Depends(get_tenant_security_correlation_service),
) -> CorrelationEvaluationResponse:
    """Runs the server-controlled correlation rule registry for this
    tenant. Never accepts rule code or rule input from the caller."""
    summary = await service.evaluate(tenant.organization_id)
    return CorrelationEvaluationResponse(**dataclasses.asdict(summary))


@router.get("", response_model=list[SecurityCorrelationResponse])
async def list_security_correlations(
    lifecycle: str | None = Query(default=None),
    stable_rule_id: str | None = Query(default=None),
    evidence_state: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityCorrelationService = Depends(get_tenant_security_correlation_service),
) -> list[SecurityCorrelationResponse]:
    correlations = await service.list_for_org(
        tenant.organization_id, lifecycle, stable_rule_id, evidence_state, limit, offset,
    )
    return [SecurityCorrelationResponse(**dataclasses.asdict(c)) for c in correlations]


@router.get("/{correlation_id}", response_model=SecurityCorrelationResponse)
async def get_security_correlation(
    correlation_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityCorrelationService = Depends(get_tenant_security_correlation_service),
) -> SecurityCorrelationResponse:
    try:
        correlation = await service.get_for_org(correlation_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return SecurityCorrelationResponse(**dataclasses.asdict(correlation))
