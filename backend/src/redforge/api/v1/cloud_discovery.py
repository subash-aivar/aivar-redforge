"""M26 Phase 2 internal APIs — asset discovery and inventory queries."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field

from redforge.api.dependencies import get_asset_discovery_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.discovery_dtos import (
    GetCloudAssetQuery,
    ListAssetRelationshipsQuery,
    ListCloudAssetsQuery,
    TriggerAssetDiscoveryCommand,
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.asset_discovery_service import AssetDiscoveryService

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class TriggerDiscoveryRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    asset_types: list[str] = Field(default_factory=list)


class DiscoveryResultResponse(BaseModel):
    cloud_account_id: UUID
    organization_id: str
    sync_status: str
    discovered_count: int
    updated_count: int
    resurrected_count: int
    deleted_count: int
    projected_count: int


class AssetRelationshipResponse(BaseModel):
    relationship_id: str
    relationship_type: str
    target_provider_id: str
    target_asset_id: UUID | None


class CloudAssetResponse(BaseModel):
    asset_id: UUID
    cloud_account_id: UUID
    organization_id: str
    asset_type: str
    provider_id: str
    display_name: str
    region_code: str
    az_name: str | None
    tags: dict[str, str]
    config_hash: str
    is_deleted: bool
    last_seen_at: str
    first_seen_at: str
    created_at: str
    updated_at: str
    version: int
    relationships: list[AssetRelationshipResponse] = Field(default_factory=list)
    normalized_config: dict[str, Any] = Field(default_factory=dict)
    provider_metadata: dict[str, Any] = Field(default_factory=dict)


class CloudAssetPageResponse(BaseModel):
    items: list[CloudAssetResponse]
    page: int
    size: int
    total: int


def _relationship_response(dto: object) -> AssetRelationshipResponse:
    target = getattr(dto, "target_asset_id", None)
    return AssetRelationshipResponse(
        relationship_id=str(dto.relationship_id),  # type: ignore[attr-defined]
        relationship_type=str(dto.relationship_type),  # type: ignore[attr-defined]
        target_provider_id=str(dto.target_provider_id),  # type: ignore[attr-defined]
        target_asset_id=UUID(str(target)) if target else None,
    )


def _asset_response(dto: object) -> CloudAssetResponse:
    return CloudAssetResponse(
        asset_id=UUID(str(dto.asset_id)),  # type: ignore[attr-defined]
        cloud_account_id=UUID(str(dto.cloud_account_id)),  # type: ignore[attr-defined]
        organization_id=str(dto.organization_id),  # type: ignore[attr-defined]
        asset_type=str(dto.asset_type),  # type: ignore[attr-defined]
        provider_id=str(dto.provider_id),  # type: ignore[attr-defined]
        display_name=str(dto.display_name),  # type: ignore[attr-defined]
        region_code=str(dto.region_code),  # type: ignore[attr-defined]
        az_name=str(dto.az_name) if dto.az_name else None,  # type: ignore[attr-defined]
        tags=dict(dto.tags),  # type: ignore[attr-defined]
        config_hash=str(dto.config_hash),  # type: ignore[attr-defined]
        is_deleted=bool(dto.is_deleted),  # type: ignore[attr-defined]
        last_seen_at=dto.last_seen_at.isoformat(),  # type: ignore[attr-defined]
        first_seen_at=dto.first_seen_at.isoformat(),  # type: ignore[attr-defined]
        created_at=dto.created_at.isoformat(),  # type: ignore[attr-defined]
        updated_at=dto.updated_at.isoformat(),  # type: ignore[attr-defined]
        version=int(dto.version),  # type: ignore[attr-defined]
        relationships=[_relationship_response(r) for r in dto.relationships],  # type: ignore[attr-defined]
        normalized_config=dict(dto.normalized_config or {}),  # type: ignore[attr-defined]
        provider_metadata=dict(dto.provider_metadata or {}),  # type: ignore[attr-defined]
    )


@router.post(
    "/accounts/{account_id}/discover",
    status_code=status.HTTP_200_OK,
    response_model=DiscoveryResultResponse,
)
async def trigger_asset_discovery(
    account_id: UUID,
    body: TriggerDiscoveryRequest | None = None,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: AssetDiscoveryService = Depends(get_asset_discovery_service),
) -> DiscoveryResultResponse:
    request = body or TriggerDiscoveryRequest()
    dto = await service.discover_account(
        TriggerAssetDiscoveryCommand(
            organization_id=tenant.organization_id,
            cloud_account_id=str(account_id),
            asset_types=tuple(request.asset_types),
        )
    )
    return DiscoveryResultResponse(
        cloud_account_id=UUID(dto.cloud_account_id),
        organization_id=dto.organization_id,
        sync_status=dto.sync_status,
        discovered_count=dto.discovered_count,
        updated_count=dto.updated_count,
        resurrected_count=dto.resurrected_count,
        deleted_count=dto.deleted_count,
        projected_count=dto.projected_count,
    )


@router.get("/assets", response_model=CloudAssetPageResponse)
async def list_cloud_assets(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: AssetDiscoveryService = Depends(get_asset_discovery_service),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
    cloud_account_id: UUID | None = None,
    asset_type: str | None = None,
    include_deleted: bool = Query(default=False),
) -> CloudAssetPageResponse:
    result = await service.list_cloud_assets(
        ListCloudAssetsQuery(
            organization_id=tenant.organization_id,
            page=page,
            size=size,
            cloud_account_id=str(cloud_account_id) if cloud_account_id else None,
            asset_type=asset_type,
            include_deleted=include_deleted,
        )
    )
    return CloudAssetPageResponse(
        items=[_asset_response(item) for item in result.items],
        page=result.page,
        size=result.size,
        total=result.total,
    )


@router.get("/assets/{asset_id}", response_model=CloudAssetResponse)
async def get_cloud_asset(
    asset_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: AssetDiscoveryService = Depends(get_asset_discovery_service),
) -> CloudAssetResponse:
    dto = await service.get_cloud_asset(
        GetCloudAssetQuery(
            organization_id=tenant.organization_id,
            asset_id=str(asset_id),
        )
    )
    return _asset_response(dto)


@router.get(
    "/assets/{asset_id}/relationships",
    response_model=list[AssetRelationshipResponse],
)
async def list_asset_relationships(
    asset_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: AssetDiscoveryService = Depends(get_asset_discovery_service),
) -> list[AssetRelationshipResponse]:
    items = await service.list_asset_relationships(
        ListAssetRelationshipsQuery(
            organization_id=tenant.organization_id,
            asset_id=str(asset_id),
        )
    )
    return [_relationship_response(item) for item in items]
