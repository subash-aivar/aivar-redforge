from __future__ import annotations

import pytest

from siem_search.application.exceptions import (
    AmbiguousProviderSelectionError,
    DuplicateProviderRegistrationError,
    UnsupportedProviderError,
    UnsupportedProviderVersionError,
)
from siem_search.application.registry.in_memory_search_provider_registry import (
    InMemorySearchProviderRegistry,
)
from siem_search.domain.value_objects.enums import SearchEntityType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import FakeSearchProvider


def test_register_then_resolve_returns_same_provider() -> None:
    registry = InMemorySearchProviderRegistry()
    provider = FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 0))
    registry.register(provider)

    assert registry.resolve(SearchEntityType.EVENTS, SchemaVersion(1, 0)) is provider


def test_resolve_matches_compatible_minor_version() -> None:
    registry = InMemorySearchProviderRegistry()
    provider = FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 3))
    registry.register(provider)

    assert registry.resolve(SearchEntityType.EVENTS, SchemaVersion(1, 0)) is provider


def test_is_registered() -> None:
    registry = InMemorySearchProviderRegistry()
    registry.register(FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 0)))

    assert registry.is_registered(SearchEntityType.EVENTS, SchemaVersion(1, 0)) is True
    assert registry.is_registered(SearchEntityType.EVENTS, SchemaVersion(2, 0)) is False


def test_duplicate_registration_raises() -> None:
    registry = InMemorySearchProviderRegistry()
    registry.register(FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 0)))

    with pytest.raises(DuplicateProviderRegistrationError):
        registry.register(FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 0)))


def test_different_entity_types_do_not_conflict() -> None:
    registry = InMemorySearchProviderRegistry()
    registry.register(FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 0)))
    registry.register(FakeSearchProvider(SearchEntityType.ALERTS, SchemaVersion(1, 0)))

    assert registry.is_registered(SearchEntityType.EVENTS, SchemaVersion(1, 0))
    assert registry.is_registered(SearchEntityType.ALERTS, SchemaVersion(1, 0))


def test_resolve_unregistered_entity_type_raises() -> None:
    registry = InMemorySearchProviderRegistry()
    with pytest.raises(UnsupportedProviderError):
        registry.resolve(SearchEntityType.DETECTIONS, SchemaVersion(1, 0))


def test_resolve_incompatible_major_raises() -> None:
    registry = InMemorySearchProviderRegistry()
    registry.register(FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 0)))

    with pytest.raises(UnsupportedProviderVersionError):
        registry.resolve(SearchEntityType.EVENTS, SchemaVersion(2, 0))


def test_resolve_ambiguous_when_two_compatible_versions_registered() -> None:
    registry = InMemorySearchProviderRegistry()
    registry.register(FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 0)))
    registry.register(FakeSearchProvider(SearchEntityType.EVENTS, SchemaVersion(1, 5)))

    with pytest.raises(AmbiguousProviderSelectionError) as exc_info:
        registry.resolve(SearchEntityType.EVENTS, SchemaVersion(1, 0))

    assert exc_info.value.entity_type == SearchEntityType.EVENTS
    assert len(exc_info.value.candidate_versions) == 2
