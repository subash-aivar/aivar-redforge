"""Security Condition REST API — M8.

Tenant-scoped, READ-ONLY plus explicit `resolve` only. No endpoint
accepts a `SecurityConditionInput`-shaped body — canonical conditions
are created exclusively by M6/M7 (and future) analyzer integrations
calling `TenantSecurityConditionService.ingest()` directly; the
frontend/browser can never fabricate a canonical security fact,
forge a severity, or set `evidence_state=validated` itself.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_security_condition_service
from redforge.api.security import TenantContext, require_permission
from redforge.core.exceptions import NotFoundError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.security_conditions.service import TenantSecurityConditionService

router = APIRouter(prefix="/security-conditions", tags=["security-conditions"])


class SecurityConditionResponse(BaseModel):
    id: str
    organization_id: str
    affected_asset_id: str
    source_category: str
    stable_rule_id: str
    evidence_state: str
    severity: str
    title: str
    summary: str
    remediation: str
    canonical_references: list[str]
    evidence: list[dict[str, str]]
    lifecycle: str
    first_observed_at: str
    last_observed_at: str


class SecurityConditionSummaryResponse(BaseModel):
    by_evidence_state: dict[str, int]
    by_severity: dict[str, int]
    by_source_category: dict[str, int]
    by_lifecycle: dict[str, int]


@router.get("/summary", response_model=SecurityConditionSummaryResponse)
async def get_security_condition_summary(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityConditionService = Depends(get_tenant_security_condition_service),
) -> SecurityConditionSummaryResponse:
    """Backend-computed aggregate counts — a real `GROUP BY COUNT(*)`
    query per dimension, never a frontend tally over one paginated
    page of rows. Must be registered before `/{condition_id}` so
    `summary` is never captured as a condition ID path param."""
    summary = await service.get_summary_for_org(tenant.organization_id)
    return SecurityConditionSummaryResponse(**dataclasses.asdict(summary))


@router.get("", response_model=list[SecurityConditionResponse])
async def list_security_conditions(
    evidence_state: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source_category: str | None = Query(default=None),
    asset_kind: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityConditionService = Depends(get_tenant_security_condition_service),
) -> list[SecurityConditionResponse]:
    conditions = await service.list_for_org(
        tenant.organization_id, evidence_state, severity, source_category,
        asset_kind, limit, offset,
    )
    return [SecurityConditionResponse(**dataclasses.asdict(c)) for c in conditions]


@router.get("/{condition_id}", response_model=SecurityConditionResponse)
async def get_security_condition(
    condition_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityConditionService = Depends(get_tenant_security_condition_service),
) -> SecurityConditionResponse:
    try:
        condition = await service.get_for_org(condition_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return SecurityConditionResponse(**dataclasses.asdict(condition))


@router.post("/{condition_id}/resolve", response_model=SecurityConditionResponse)
async def resolve_security_condition(
    condition_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantSecurityConditionService = Depends(get_tenant_security_condition_service),
) -> SecurityConditionResponse:
    """Explicit resolution only — never automatic. Requires write
    permission since it changes lifecycle state, unlike every other
    endpoint in this router."""
    try:
        condition = await service.resolve_condition(condition_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return SecurityConditionResponse(**dataclasses.asdict(condition))
