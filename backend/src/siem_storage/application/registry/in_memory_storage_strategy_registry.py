"""InMemoryStorageStrategyRegistry — the one concrete registry this
milestone implements (M43E §4). Keyed by `StorageTier` — at most one
strategy per tier, since a tier's planning behavior must be
unambiguous. No persistence, no DI container wiring — a plain
in-process dict, per this milestone's explicit scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_storage.application.exceptions import (
    DuplicateStorageStrategyRegistrationError,
    UnsupportedStorageTierError,
)

if TYPE_CHECKING:
    from siem_storage.application.ports.i_storage_strategy import IStorageStrategy
    from siem_storage.domain.value_objects.enums import StorageTier


class InMemoryStorageStrategyRegistry:
    def __init__(self) -> None:
        self._by_tier: dict[StorageTier, IStorageStrategy] = {}

    def register(self, strategy: IStorageStrategy) -> None:
        if strategy.tier in self._by_tier:
            raise DuplicateStorageStrategyRegistrationError(strategy.tier)
        self._by_tier[strategy.tier] = strategy

    def resolve(self, tier: StorageTier) -> IStorageStrategy:
        strategy = self._by_tier.get(tier)
        if strategy is None:
            raise UnsupportedStorageTierError(tier)
        return strategy

    def is_registered(self, tier: StorageTier) -> bool:
        return tier in self._by_tier
