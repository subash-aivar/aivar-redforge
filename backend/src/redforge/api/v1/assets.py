"""Asset inventory REST API — M3.

Tenant-scoped throughout: `organization_id` is ALWAYS `tenant.organization_id`
from the verified JWT (never a client-supplied value). A cross-tenant
guessed asset ID returns 404, identically to a nonexistent one — see
`TenantAssetService.get_for_org` / `SqlAlchemyAssetRepository.get_by_id_for_org`,
which filter at the query level rather than fetching-then-checking.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_asset_service
from redforge.api.security import TenantContext, require_permission
from redforge.core.exceptions import NotFoundError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetResponse(BaseModel):
    id: str
    organization_id: str
    asset_type: str
    name: str
    description: str
    external_id: str
    discovery_source: str
    lifecycle_stage: str
    health_status: str
    first_observed_at: str
    last_observed_at: str
    relationship_count: int
    associated_target_id: str | None


class AssetRelationshipResponse(BaseModel):
    relationship_id: str
    target_asset_id: str
    relationship_type: str
    label: str


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    asset_type: str | None = Query(default=None),
    lifecycle_stage: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantAssetService = Depends(get_tenant_asset_service),
) -> list[AssetResponse]:
    """List canonical assets owned by the caller's organization."""
    assets = await service.list_for_org(
        tenant.organization_id, asset_type, lifecycle_stage, limit, offset,
    )
    return [AssetResponse(**dataclasses.asdict(a)) for a in assets]


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantAssetService = Depends(get_tenant_asset_service),
) -> AssetResponse:
    """404s identically for a nonexistent ID or one owned by another
    organization — a cross-tenant caller cannot distinguish the two."""
    try:
        asset = await service.get_for_org(asset_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return AssetResponse(**dataclasses.asdict(asset))


@router.get("/{asset_id}/relationships", response_model=list[AssetRelationshipResponse])
async def get_asset_relationships(
    asset_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantAssetService = Depends(get_tenant_asset_service),
) -> list[AssetRelationshipResponse]:
    try:
        rels = await service.get_relationships_for_org(asset_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return [AssetRelationshipResponse(**r) for r in rels]
