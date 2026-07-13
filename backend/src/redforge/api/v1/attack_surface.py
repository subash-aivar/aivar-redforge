"""Attack Surface REST API — M9.

Tenant-scoped, read-only. Backend-computed facts only — no magic
0-100 risk score, no client-side aggregation. Asset browsing itself
stays on the generic `/assets` API (M3); this router adds only the
M9-specific exposure-summary capability.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_attack_surface_service
from redforge.api.security import TenantContext, require_permission
from redforge.core.exceptions import NotFoundError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.security_correlation.attack_surface import (
        TenantAttackSurfaceService,
    )

router = APIRouter(prefix="/attack-surface", tags=["attack-surface"])


class AttackSurfaceSummaryResponse(BaseModel):
    assets_with_active_conditions: int
    assets_with_multiple_active_conditions: int
    active_correlations: int
    external_classification_breakdown: dict[str, int]
    evidence_state_breakdown: dict[str, int]


class AssetExposureSummaryResponse(BaseModel):
    asset_id: str
    asset_name: str
    asset_kind: str
    external_classification: str
    active_condition_count: int
    observed_condition_count: int
    inferred_condition_count: int
    validated_condition_count: int
    highest_active_severity: str
    active_source_categories: list[str]
    sensitive_service_count: int
    active_correlation_count: int
    last_condition_observed_at: str | None


@router.get("/summary", response_model=AttackSurfaceSummaryResponse)
async def get_attack_surface_summary(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantAttackSurfaceService = Depends(get_tenant_attack_surface_service),
) -> AttackSurfaceSummaryResponse:
    summary = await service.get_summary_for_org(tenant.organization_id)
    return AttackSurfaceSummaryResponse(**dataclasses.asdict(summary))


@router.get("/assets/{asset_id}", response_model=AssetExposureSummaryResponse)
async def get_asset_exposure_summary(
    asset_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantAttackSurfaceService = Depends(get_tenant_attack_surface_service),
) -> AssetExposureSummaryResponse:
    try:
        summary = await service.get_asset_exposure_summary(tenant.organization_id, asset_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return AssetExposureSummaryResponse(**dataclasses.asdict(summary))
