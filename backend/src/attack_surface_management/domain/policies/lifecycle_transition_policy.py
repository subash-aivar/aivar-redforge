"""Lifecycle transition policies for attack_surface_management (M49A).

Encodes the allowed state graphs as static, side-effect-free lookups so
both the aggregates (as a guard) and callers/tests (to query legality
without mutating anything) can consult the same rule."""

from __future__ import annotations

from attack_surface_management.domain.value_objects.enums import (
    AssetLifecycleState,
    NetworkRangeLifecycleState,
)

_ASSET_TRANSITIONS: dict[AssetLifecycleState, frozenset[AssetLifecycleState]] = {
    AssetLifecycleState.DISCOVERED: frozenset(
        {AssetLifecycleState.VALIDATED, AssetLifecycleState.IGNORED}
    ),
    AssetLifecycleState.VALIDATED: frozenset(
        {AssetLifecycleState.ACTIVE, AssetLifecycleState.IGNORED}
    ),
    AssetLifecycleState.ACTIVE: frozenset({AssetLifecycleState.DECOMMISSIONED}),
    AssetLifecycleState.DECOMMISSIONED: frozenset(),
    AssetLifecycleState.IGNORED: frozenset(),
}

_NETWORK_RANGE_TRANSITIONS: dict[
    NetworkRangeLifecycleState, frozenset[NetworkRangeLifecycleState]
] = {
    NetworkRangeLifecycleState.DISCOVERED: frozenset({NetworkRangeLifecycleState.ACTIVE}),
    NetworkRangeLifecycleState.ACTIVE: frozenset({NetworkRangeLifecycleState.RETIRED}),
    NetworkRangeLifecycleState.RETIRED: frozenset(),
}


class AssetLifecycleTransitionPolicy:
    """`DISCOVERED -> VALIDATED -> ACTIVE -> DECOMMISSIONED`, with
    `IGNORED` reachable from `DISCOVERED`/`VALIDATED` as a terminal
    false-positive/out-of-scope outcome."""

    @staticmethod
    def is_allowed(from_state: AssetLifecycleState, to_state: AssetLifecycleState) -> bool:
        return to_state in _ASSET_TRANSITIONS.get(from_state, frozenset())


class NetworkRangeLifecycleTransitionPolicy:
    """`DISCOVERED -> ACTIVE -> RETIRED`, terminal at `RETIRED`."""

    @staticmethod
    def is_allowed(
        from_state: NetworkRangeLifecycleState, to_state: NetworkRangeLifecycleState
    ) -> bool:
        return to_state in _NETWORK_RANGE_TRANSITIONS.get(from_state, frozenset())
