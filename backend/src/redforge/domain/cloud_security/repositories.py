"""Repository interfaces and paging types for M26 Cloud Security."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    CloudAssetType,
    CloudIAMPrincipalId,
    CloudProviderId,
    CloudProviderType,
    IAMPrincipalType,
    OrganizationId,
)


@dataclass(frozen=True, slots=True)
class Page[T]:
    items: list[T]
    page: int
    size: int
    total: int


class CloudProviderRepository(Protocol):
    async def save(self, provider: CloudProvider) -> None: ...

    async def get_by_id(
        self, provider_id: CloudProviderId, organization_id: OrganizationId
    ) -> CloudProvider | None: ...

    async def list_by_organization(self, org_id: OrganizationId) -> list[CloudProvider]: ...

    async def get_by_org_and_type(
        self, org_id: OrganizationId, provider_type: CloudProviderType
    ) -> CloudProvider | None: ...


class CloudAccountRepository(Protocol):
    async def save(self, account: CloudAccount) -> None: ...

    async def get_by_id(
        self, account_id: CloudAccountId, organization_id: OrganizationId
    ) -> CloudAccount | None: ...

    async def list_by_provider(
        self, provider_id: CloudProviderId, organization_id: OrganizationId
    ) -> list[CloudAccount]: ...

    async def list_by_organization(
        self, org_id: OrganizationId, *, page: int, size: int
    ) -> Page[CloudAccount]: ...

    async def get_by_external_id(
        self,
        provider_type: CloudProviderType,
        external_id: str,
        org_id: OrganizationId,
    ) -> CloudAccount | None: ...


class CloudAssetRepository(Protocol):
    async def save(self, asset: CloudAsset) -> None: ...

    async def save_batch(self, assets: list[CloudAsset]) -> None: ...

    async def get_by_id(
        self, asset_id: CloudAssetId, organization_id: OrganizationId
    ) -> CloudAsset | None: ...

    async def get_by_provider_id(
        self,
        account_id: CloudAccountId,
        provider_id: str,
        organization_id: OrganizationId,
    ) -> CloudAsset | None: ...

    async def list_by_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        asset_type: CloudAssetType | None,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
    ) -> Page[CloudAsset]: ...

    async def list_by_organization(
        self,
        org_id: OrganizationId,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
        cloud_account_id: CloudAccountId | None = None,
        asset_type: CloudAssetType | None = None,
    ) -> Page[CloudAsset]: ...

    async def mark_deleted(
        self,
        provider_ids_seen: set[str],
        account_id: CloudAccountId,
        organization_id: OrganizationId,
    ) -> list[CloudAsset]: ...

    async def list_provider_ids_for_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        *,
        include_deleted: bool = False,
    ) -> dict[str, CloudAssetId]: ...


class CloudIAMPrincipalRepository(Protocol):
    async def save(self, principal: CloudIAMPrincipal) -> None: ...

    async def save_batch(self, principals: list[CloudIAMPrincipal]) -> None: ...

    async def get_by_id(
        self, principal_id: CloudIAMPrincipalId, organization_id: OrganizationId
    ) -> CloudIAMPrincipal | None: ...

    async def get_by_provider_id(
        self,
        account_id: CloudAccountId,
        provider_id: str,
        organization_id: OrganizationId,
    ) -> CloudIAMPrincipal | None: ...

    async def list_by_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        principal_type: IAMPrincipalType | None,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
    ) -> Page[CloudIAMPrincipal]: ...

    async def list_by_organization(
        self,
        org_id: OrganizationId,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
        cloud_account_id: CloudAccountId | None = None,
        principal_type: IAMPrincipalType | None = None,
    ) -> Page[CloudIAMPrincipal]: ...

    async def mark_deleted(
        self,
        provider_ids_seen: set[str],
        account_id: CloudAccountId,
        organization_id: OrganizationId,
    ) -> list[CloudIAMPrincipal]: ...

    async def list_provider_ids_for_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        *,
        include_deleted: bool = False,
    ) -> dict[str, CloudIAMPrincipalId]: ...
