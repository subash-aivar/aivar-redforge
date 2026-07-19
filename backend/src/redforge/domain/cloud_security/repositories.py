"""Repository interfaces and paging types for M26 Cloud Security foundation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudProviderId,
    CloudProviderType,
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
