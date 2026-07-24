"""Immutable CQRS query objects for Resource Discovery (M45E)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        DiscoveryJobId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class GetDiscoveryStatusQuery:
    tenant_id: TenantId
    job_id: DiscoveryJobId


@dataclass(frozen=True, slots=True)
class ListDiscoveryJobsQuery:
    tenant_id: TenantId
    account_id: AccountId | None = None


@dataclass(frozen=True, slots=True)
class ListDiscoveredAssetsQuery:
    tenant_id: TenantId
    job_id: DiscoveryJobId


@dataclass(frozen=True, slots=True)
class DiscoveryStatisticsQuery:
    tenant_id: TenantId
    account_id: AccountId | None = None
