"""NetworkRange — the second aggregate root of attack_surface_management
(M49A): a discovered CIDR block tracked independently of the assets
found within it. See `Asset`'s module docstring for the full boundary
rationale — a range groups many assets (inverse cardinality of
`Asset`'s port/certificate/DNS-record ownership), so `Asset`s are never
attached to a `NetworkRange` by object reference, only counted."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.domain.events.network_range_events import (
    NetworkRangeActivated,
    NetworkRangeAssetCountUpdated,
    NetworkRangeDiscovered,
    NetworkRangeRetired,
)
from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidNegativeCountError,
    InvalidNetworkRangeLifecycleTransition,
    TenantMismatch,
)
from attack_surface_management.domain.policies.lifecycle_transition_policy import (
    NetworkRangeLifecycleTransitionPolicy,
)
from attack_surface_management.domain.value_objects.enums import (
    DiscoverySource,
    NetworkRangeLifecycleState,
)

if TYPE_CHECKING:
    from datetime import datetime

    from attack_surface_management.domain.events.base import BaseDomainEvent
    from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
    from attack_surface_management.domain.value_objects.identifiers import (
        NetworkRangeId,
        TenantId,
    )


class NetworkRange:
    __slots__ = (
        "_pending_events",
        "asset_count",
        "cidr",
        "created_at",
        "discovery_source",
        "lifecycle_state",
        "range_id",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        range_id: NetworkRangeId,
        tenant_id: TenantId,
        cidr: CidrBlock,
        created_at: datetime,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL_ENTRY,
        lifecycle_state: NetworkRangeLifecycleState = NetworkRangeLifecycleState.DISCOVERED,
        asset_count: int = 0,
        updated_at: datetime | None = None,
    ) -> None:
        if asset_count < 0:
            raise InvalidNegativeCountError("asset_count", asset_count)
        self.range_id = range_id
        self.tenant_id = tenant_id
        self.cidr = cidr
        self.discovery_source = discovery_source
        self.lifecycle_state = lifecycle_state
        self.asset_count = asset_count
        self.created_at = created_at
        self.updated_at = updated_at or created_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def _create(
        cls,
        range_id: NetworkRangeId,
        tenant_id: TenantId,
        cidr: CidrBlock,
        now: datetime,
        discovery_source: DiscoverySource,
    ) -> NetworkRange:
        """Internal constructor used only by `NetworkRangeFactory`."""
        network_range = cls(
            range_id=range_id,
            tenant_id=tenant_id,
            cidr=cidr,
            created_at=now,
            discovery_source=discovery_source,
        )
        network_range._emit(
            NetworkRangeDiscovered(
                tenant_id=str(tenant_id),
                aggregate_id=str(range_id),
                aggregate_type="NetworkRange",
                occurred_at=now,
                cidr=str(cidr),
            )
        )
        return network_range

    def record_asset_count(self, tenant_id: TenantId, count: int, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if count < 0:
            raise InvalidNegativeCountError("asset_count", count)
        if count == self.asset_count:
            return
        previous = self.asset_count
        self.asset_count = count
        self.updated_at = now
        self._emit(
            NetworkRangeAssetCountUpdated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.range_id),
                aggregate_type="NetworkRange",
                occurred_at=now,
                previous_count=previous,
                new_count=count,
            )
        )

    def activate(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not NetworkRangeLifecycleTransitionPolicy.is_allowed(
            self.lifecycle_state, NetworkRangeLifecycleState.ACTIVE
        ):
            raise InvalidNetworkRangeLifecycleTransition(
                self.lifecycle_state.value, NetworkRangeLifecycleState.ACTIVE.value
            )
        self.lifecycle_state = NetworkRangeLifecycleState.ACTIVE
        self.updated_at = now
        self._emit(
            NetworkRangeActivated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.range_id),
                aggregate_type="NetworkRange",
                occurred_at=now,
            )
        )

    def retire(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not NetworkRangeLifecycleTransitionPolicy.is_allowed(
            self.lifecycle_state, NetworkRangeLifecycleState.RETIRED
        ):
            raise InvalidNetworkRangeLifecycleTransition(
                self.lifecycle_state.value, NetworkRangeLifecycleState.RETIRED.value
            )
        self.lifecycle_state = NetworkRangeLifecycleState.RETIRED
        self.updated_at = now
        self._emit(
            NetworkRangeRetired(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.range_id),
                aggregate_type="NetworkRange",
                occurred_at=now,
            )
        )
