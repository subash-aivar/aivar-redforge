"""Immutable CQRS command objects for `NetworkRange` lifecycle (M49B)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
    from attack_surface_management.domain.value_objects.enums import DiscoverySource
    from attack_surface_management.domain.value_objects.identifiers import (
        NetworkRangeId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class FormNetworkRangeCommand:
    tenant_id: TenantId
    cidr: CidrBlock
    discovery_source: DiscoverySource | None = None
    range_id: NetworkRangeId | None = None


@dataclass(frozen=True, slots=True)
class RecordNetworkRangeAssetCountCommand:
    tenant_id: TenantId
    range_id: NetworkRangeId
    count: int


@dataclass(frozen=True, slots=True)
class ActivateNetworkRangeCommand:
    tenant_id: TenantId
    range_id: NetworkRangeId


@dataclass(frozen=True, slots=True)
class RetireNetworkRangeCommand:
    tenant_id: TenantId
    range_id: NetworkRangeId
