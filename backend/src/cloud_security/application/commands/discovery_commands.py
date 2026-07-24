"""Immutable CQRS command objects for Resource Discovery (M45E).
`CloudDiscoveryJob` remains the single aggregate these commands act
against; syncing discovered resources into `CloudAsset` (M45B) is an
orchestration responsibility of `DiscoveryApplicationService`, never a
new ownership claim over assets."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        DiscoveryJobId,
        ProviderId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class StartDiscoveryCommand:
    tenant_id: TenantId
    account_id: AccountId
    provider_id: ProviderId
    window: DiscoveryWindow


@dataclass(frozen=True, slots=True)
class DiscoverAccountCommand:
    tenant_id: TenantId
    account_id: AccountId
    provider_id: ProviderId
    window: DiscoveryWindow


@dataclass(frozen=True, slots=True)
class DiscoverOrganizationCommand:
    tenant_id: TenantId
    provider_id: ProviderId
    account_ids: tuple[AccountId, ...]
    window: DiscoveryWindow


@dataclass(frozen=True, slots=True)
class RefreshDiscoveryCommand:
    tenant_id: TenantId
    job_id: DiscoveryJobId
    window: DiscoveryWindow


@dataclass(frozen=True, slots=True)
class CancelDiscoveryCommand:
    tenant_id: TenantId
    job_id: DiscoveryJobId


@dataclass(frozen=True, slots=True)
class BatchDiscoveryCommand:
    tenant_id: TenantId
    commands: tuple[StartDiscoveryCommand, ...] = field(default_factory=tuple)
