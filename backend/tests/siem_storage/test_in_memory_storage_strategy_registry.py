from __future__ import annotations

import pytest

from siem_storage.application.exceptions import (
    DuplicateStorageStrategyRegistrationError,
    UnsupportedStorageTierError,
)
from siem_storage.application.registry.in_memory_storage_strategy_registry import (
    InMemoryStorageStrategyRegistry,
)
from siem_storage.domain.value_objects.enums import StorageTier

from .conftest import FakeStorageStrategy


def test_register_then_resolve_returns_same_strategy() -> None:
    registry = InMemoryStorageStrategyRegistry()
    strategy = FakeStorageStrategy(StorageTier.HOT)
    registry.register(strategy)

    assert registry.resolve(StorageTier.HOT) is strategy


def test_is_registered() -> None:
    registry = InMemoryStorageStrategyRegistry()
    registry.register(FakeStorageStrategy(StorageTier.HOT))

    assert registry.is_registered(StorageTier.HOT) is True
    assert registry.is_registered(StorageTier.WARM) is False


def test_duplicate_registration_same_tier_raises() -> None:
    registry = InMemoryStorageStrategyRegistry()
    registry.register(FakeStorageStrategy(StorageTier.HOT))

    with pytest.raises(DuplicateStorageStrategyRegistrationError):
        registry.register(FakeStorageStrategy(StorageTier.HOT))


def test_different_tiers_do_not_conflict() -> None:
    registry = InMemoryStorageStrategyRegistry()
    registry.register(FakeStorageStrategy(StorageTier.HOT))
    registry.register(FakeStorageStrategy(StorageTier.WARM))

    assert registry.is_registered(StorageTier.HOT)
    assert registry.is_registered(StorageTier.WARM)


def test_resolve_unregistered_tier_raises() -> None:
    registry = InMemoryStorageStrategyRegistry()
    with pytest.raises(UnsupportedStorageTierError):
        registry.resolve(StorageTier.COLD)
