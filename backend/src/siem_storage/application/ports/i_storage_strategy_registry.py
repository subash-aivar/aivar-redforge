"""IStorageStrategyRegistry — registration/lookup contract (M43E §3/§4).

`InMemoryStorageStrategyRegistry` (M43E §4) is this milestone's one
concrete implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_storage.application.ports.i_storage_strategy import IStorageStrategy
    from siem_storage.domain.value_objects.enums import StorageTier


class IStorageStrategyRegistry(Protocol):
    def register(self, strategy: IStorageStrategy) -> None:
        """Raises `DuplicateStorageStrategyRegistrationError` if a
        strategy for the same tier is already registered."""
        ...

    def resolve(self, tier: StorageTier) -> IStorageStrategy:
        """Raises `UnsupportedStorageTierError` if no strategy is
        registered for `tier`."""
        ...

    def is_registered(self, tier: StorageTier) -> bool: ...
