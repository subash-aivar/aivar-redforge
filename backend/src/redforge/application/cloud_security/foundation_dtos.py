"""Application commands, queries, and DTOs for M26 Cloud Security foundation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class RegisterCloudProviderCommand:
    organization_id: str
    provider_type: str
    display_name: str
    polling_interval_seconds: int = 3600
    region_filter: tuple[str, ...] = ()
    service_filter: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UpdateCloudProviderCommand:
    organization_id: str
    provider_id: str
    display_name: str | None = None
    polling_interval_seconds: int | None = None
    region_filter: tuple[str, ...] | None = None
    service_filter: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class DisableCloudProviderCommand:
    organization_id: str
    provider_id: str


@dataclass(frozen=True, slots=True)
class RegisterCloudAccountCommand:
    organization_id: str
    cloud_provider_id: str
    external_id: str
    display_name: str
    account_type: str
    credential_reference_id: str
    tags: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class ListCloudProvidersQuery:
    organization_id: str


@dataclass(frozen=True, slots=True)
class ListCloudAccountsQuery:
    organization_id: str
    page: int = 1
    size: int = 50
    cloud_provider_id: str | None = None


@dataclass(frozen=True, slots=True)
class CloudProviderDTO:
    provider_id: str
    organization_id: str
    provider_type: str
    display_name: str
    status: str
    polling_interval_seconds: int
    region_filter: list[str]
    service_filter: list[str]
    created_at: datetime
    updated_at: datetime
    version: int


@dataclass(frozen=True, slots=True)
class CloudAccountDTO:
    account_id: str
    cloud_provider_id: str
    organization_id: str
    external_id: str
    display_name: str
    account_type: str
    credential_reference_id: str
    sync_status: str
    tags: dict[str, str]
    created_at: datetime
    updated_at: datetime
    version: int


@dataclass(frozen=True, slots=True)
class CloudAccountPageDTO:
    items: list[CloudAccountDTO]
    page: int
    size: int
    total: int
