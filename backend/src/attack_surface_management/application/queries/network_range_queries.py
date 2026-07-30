"""Immutable CQRS query objects for `NetworkRange` (M49B)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from attack_surface_management.domain.value_objects.enums import NetworkRangeLifecycleState
    from attack_surface_management.domain.value_objects.identifiers import (
        NetworkRangeId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class GetNetworkRangeQuery:
    tenant_id: TenantId
    range_id: NetworkRangeId


@dataclass(frozen=True, slots=True)
class ListNetworkRangesQuery:
    tenant_id: TenantId
    lifecycle_state: NetworkRangeLifecycleState | None = None
    limit: int = 50
    offset: int = 0
