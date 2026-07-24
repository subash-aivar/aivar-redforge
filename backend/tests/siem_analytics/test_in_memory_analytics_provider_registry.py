from __future__ import annotations

import pytest

from siem_analytics.application.exceptions import (
    AmbiguousProviderSelectionError,
    DuplicateProviderRegistrationError,
    UnsupportedProviderError,
    UnsupportedProviderVersionError,
)
from siem_analytics.application.registry.in_memory_analytics_provider_registry import (
    InMemoryAnalyticsProviderRegistry,
)
from siem_analytics.domain.value_objects.enums import AnalyticsEntityType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import FakeAnalyticsProvider


def test_register_then_resolve_returns_same_provider() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    provider = FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0))
    registry.register(provider)

    assert registry.resolve(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)) is provider


def test_resolve_matches_compatible_minor_version() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    provider = FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 3))
    registry.register(provider)

    assert registry.resolve(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)) is provider


def test_is_registered() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    registry.register(FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)))

    assert registry.is_registered(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)) is True
    assert registry.is_registered(AnalyticsEntityType.EVENTS, SchemaVersion(2, 0)) is False


def test_duplicate_registration_raises() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    registry.register(FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)))

    with pytest.raises(DuplicateProviderRegistrationError):
        registry.register(FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)))


def test_different_entity_types_do_not_conflict() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    registry.register(FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)))
    registry.register(FakeAnalyticsProvider(AnalyticsEntityType.ALERTS, SchemaVersion(1, 0)))

    assert registry.is_registered(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0))
    assert registry.is_registered(AnalyticsEntityType.ALERTS, SchemaVersion(1, 0))


def test_resolve_unregistered_entity_type_raises() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    with pytest.raises(UnsupportedProviderError):
        registry.resolve(AnalyticsEntityType.DETECTIONS, SchemaVersion(1, 0))


def test_resolve_incompatible_major_raises() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    registry.register(FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)))

    with pytest.raises(UnsupportedProviderVersionError):
        registry.resolve(AnalyticsEntityType.EVENTS, SchemaVersion(2, 0))


def test_resolve_ambiguous_when_two_compatible_versions_registered() -> None:
    registry = InMemoryAnalyticsProviderRegistry()
    registry.register(FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0)))
    registry.register(FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, SchemaVersion(1, 5)))

    with pytest.raises(AmbiguousProviderSelectionError) as exc_info:
        registry.resolve(AnalyticsEntityType.EVENTS, SchemaVersion(1, 0))

    assert exc_info.value.entity_type == AnalyticsEntityType.EVENTS
    assert len(exc_info.value.candidate_versions) == 2
