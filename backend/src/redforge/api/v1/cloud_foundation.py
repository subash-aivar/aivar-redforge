"""M26 Phase 1 admin APIs — cloud provider and account registration/listing."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field

from redforge.api.dependencies import get_cloud_foundation_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.foundation_dtos import (
    DisableCloudProviderCommand,
    ListCloudAccountsQuery,
    ListCloudProvidersQuery,
    RegisterCloudAccountCommand,
    RegisterCloudProviderCommand,
    UpdateCloudProviderCommand,
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.foundation_service import CloudFoundationService

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class RegisterCloudProviderRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    provider_type: str
    display_name: str
    polling_interval_seconds: int = Field(default=3600, ge=60, le=604800)
    region_filter: list[str] = Field(default_factory=list)
    service_filter: list[str] = Field(default_factory=list)


class UpdateCloudProviderRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    display_name: str | None = None
    polling_interval_seconds: int | None = Field(default=None, ge=60, le=604800)
    region_filter: list[str] | None = None
    service_filter: list[str] | None = None


class RegisterCloudAccountRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    cloud_provider_id: UUID
    external_id: str
    display_name: str
    account_type: str
    credential_reference_id: str
    tags: dict[str, str] = Field(default_factory=dict)


class CloudProviderResponse(BaseModel):
    provider_id: UUID
    organization_id: str
    provider_type: str
    display_name: str
    status: str
    polling_interval_seconds: int
    region_filter: list[str]
    service_filter: list[str]
    created_at: str
    updated_at: str
    version: int


class CloudAccountResponse(BaseModel):
    account_id: UUID
    cloud_provider_id: UUID
    organization_id: str
    external_id: str
    display_name: str
    account_type: str
    credential_reference_id: str
    sync_status: str
    tags: dict[str, str]
    created_at: str
    updated_at: str
    version: int


class CloudAccountPageResponse(BaseModel):
    items: list[CloudAccountResponse]
    page: int
    size: int
    total: int


def _provider_response(dto: object) -> CloudProviderResponse:
    return CloudProviderResponse(
        provider_id=UUID(str(dto.provider_id)),  # type: ignore[attr-defined]
        organization_id=str(dto.organization_id),  # type: ignore[attr-defined]
        provider_type=str(dto.provider_type),  # type: ignore[attr-defined]
        display_name=str(dto.display_name),  # type: ignore[attr-defined]
        status=str(dto.status),  # type: ignore[attr-defined]
        polling_interval_seconds=int(dto.polling_interval_seconds),  # type: ignore[attr-defined]
        region_filter=list(dto.region_filter),  # type: ignore[attr-defined]
        service_filter=list(dto.service_filter),  # type: ignore[attr-defined]
        created_at=dto.created_at.isoformat(),  # type: ignore[attr-defined]
        updated_at=dto.updated_at.isoformat(),  # type: ignore[attr-defined]
        version=int(dto.version),  # type: ignore[attr-defined]
    )


def _account_response(dto: object) -> CloudAccountResponse:
    return CloudAccountResponse(
        account_id=UUID(str(dto.account_id)),  # type: ignore[attr-defined]
        cloud_provider_id=UUID(str(dto.cloud_provider_id)),  # type: ignore[attr-defined]
        organization_id=str(dto.organization_id),  # type: ignore[attr-defined]
        external_id=str(dto.external_id),  # type: ignore[attr-defined]
        display_name=str(dto.display_name),  # type: ignore[attr-defined]
        account_type=str(dto.account_type),  # type: ignore[attr-defined]
        credential_reference_id=str(dto.credential_reference_id),  # type: ignore[attr-defined]
        sync_status=str(dto.sync_status),  # type: ignore[attr-defined]
        tags=dict(dto.tags),  # type: ignore[attr-defined]
        created_at=dto.created_at.isoformat(),  # type: ignore[attr-defined]
        updated_at=dto.updated_at.isoformat(),  # type: ignore[attr-defined]
        version=int(dto.version),  # type: ignore[attr-defined]
    )


@router.post(
    "/providers",
    status_code=status.HTTP_201_CREATED,
    response_model=CloudProviderResponse,
)
async def register_cloud_provider(
    body: RegisterCloudProviderRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CloudFoundationService = Depends(get_cloud_foundation_service),
) -> CloudProviderResponse:
    dto = await service.register_cloud_provider(
        RegisterCloudProviderCommand(
            organization_id=tenant.organization_id,
            provider_type=body.provider_type,
            display_name=body.display_name,
            polling_interval_seconds=body.polling_interval_seconds,
            region_filter=tuple(body.region_filter),
            service_filter=tuple(body.service_filter),
        )
    )
    return _provider_response(dto)


@router.patch("/providers/{provider_id}", response_model=CloudProviderResponse)
async def update_cloud_provider(
    provider_id: UUID,
    body: UpdateCloudProviderRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CloudFoundationService = Depends(get_cloud_foundation_service),
) -> CloudProviderResponse:
    dto = await service.update_cloud_provider(
        UpdateCloudProviderCommand(
            organization_id=tenant.organization_id,
            provider_id=str(provider_id),
            display_name=body.display_name,
            polling_interval_seconds=body.polling_interval_seconds,
            region_filter=tuple(body.region_filter) if body.region_filter is not None else None,
            service_filter=tuple(body.service_filter) if body.service_filter is not None else None,
        )
    )
    return _provider_response(dto)


@router.post("/providers/{provider_id}/disable", response_model=CloudProviderResponse)
async def disable_cloud_provider(
    provider_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CloudFoundationService = Depends(get_cloud_foundation_service),
) -> CloudProviderResponse:
    dto = await service.disable_cloud_provider(
        DisableCloudProviderCommand(
            organization_id=tenant.organization_id,
            provider_id=str(provider_id),
        )
    )
    return _provider_response(dto)


@router.get("/providers", response_model=list[CloudProviderResponse])
async def list_cloud_providers(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudFoundationService = Depends(get_cloud_foundation_service),
) -> list[CloudProviderResponse]:
    items = await service.list_cloud_providers(
        ListCloudProvidersQuery(organization_id=tenant.organization_id)
    )
    return [_provider_response(item) for item in items]


@router.post(
    "/accounts",
    status_code=status.HTTP_201_CREATED,
    response_model=CloudAccountResponse,
)
async def register_cloud_account(
    body: RegisterCloudAccountRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CloudFoundationService = Depends(get_cloud_foundation_service),
) -> CloudAccountResponse:
    dto = await service.register_cloud_account(
        RegisterCloudAccountCommand(
            organization_id=tenant.organization_id,
            cloud_provider_id=str(body.cloud_provider_id),
            external_id=body.external_id,
            display_name=body.display_name,
            account_type=body.account_type,
            credential_reference_id=body.credential_reference_id,
            tags=body.tags,
        )
    )
    return _account_response(dto)


@router.get("/accounts", response_model=CloudAccountPageResponse)
async def list_cloud_accounts(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CloudFoundationService = Depends(get_cloud_foundation_service),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
    cloud_provider_id: UUID | None = None,
) -> CloudAccountPageResponse:
    result = await service.list_cloud_accounts(
        ListCloudAccountsQuery(
            organization_id=tenant.organization_id,
            page=page,
            size=size,
            cloud_provider_id=str(cloud_provider_id) if cloud_provider_id else None,
        )
    )
    return CloudAccountPageResponse(
        items=[_account_response(item) for item in result.items],
        page=result.page,
        size=result.size,
        total=result.total,
    )
