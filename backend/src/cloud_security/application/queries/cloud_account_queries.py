"""Immutable CQRS query objects for `CloudAccount` reads (M45A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import AccountId, TenantId


@dataclass(frozen=True, slots=True)
class GetCloudAccountQuery:
    tenant_id: TenantId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class ListCloudAccountsQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType | None = None
