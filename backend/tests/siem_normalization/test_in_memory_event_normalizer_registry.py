from __future__ import annotations

import pytest

from siem_normalization.application.exceptions import (
    AmbiguousNormalizerSelectionError,
    DuplicateNormalizerRegistrationError,
    UnsupportedProviderError,
    UnsupportedVersionError,
)
from siem_normalization.application.registry.in_memory_event_normalizer_registry import (
    InMemoryEventNormalizerRegistry,
)
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import FakeNormalizer


def test_register_then_resolve_returns_same_normalizer() -> None:
    registry = InMemoryEventNormalizerRegistry()
    normalizer = FakeNormalizer("okta", SchemaVersion(1, 0))
    registry.register(normalizer)

    resolved = registry.resolve("okta", SchemaVersion(1, 0))

    assert resolved is normalizer


def test_resolve_matches_compatible_minor_version() -> None:
    """M37 §2.3: minor bumps are additive-only, so a normalizer
    registered at 1.3 must satisfy a request for 1.0."""
    registry = InMemoryEventNormalizerRegistry()
    normalizer = FakeNormalizer("okta", SchemaVersion(1, 3))
    registry.register(normalizer)

    resolved = registry.resolve("okta", SchemaVersion(1, 0))

    assert resolved is normalizer


def test_is_registered_true_after_registration() -> None:
    registry = InMemoryEventNormalizerRegistry()
    normalizer = FakeNormalizer("okta", SchemaVersion(1, 0))
    registry.register(normalizer)

    assert registry.is_registered("okta", SchemaVersion(1, 0)) is True
    assert registry.is_registered("okta", SchemaVersion(2, 0)) is False


def test_duplicate_registration_same_provider_and_version_raises() -> None:
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("okta", SchemaVersion(1, 0)))

    with pytest.raises(DuplicateNormalizerRegistrationError):
        registry.register(FakeNormalizer("okta", SchemaVersion(1, 0)))


def test_same_provider_different_exact_version_is_allowed() -> None:
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("okta", SchemaVersion(1, 0)))
    registry.register(FakeNormalizer("okta", SchemaVersion(2, 0)))  # different major, no conflict

    assert registry.is_registered("okta", SchemaVersion(1, 0))
    assert registry.is_registered("okta", SchemaVersion(2, 0))


def test_different_providers_do_not_conflict() -> None:
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("okta", SchemaVersion(1, 0)))
    registry.register(FakeNormalizer("azure-ad", SchemaVersion(1, 0)))

    assert registry.is_registered("okta", SchemaVersion(1, 0))
    assert registry.is_registered("azure-ad", SchemaVersion(1, 0))


def test_resolve_unknown_provider_raises() -> None:
    registry = InMemoryEventNormalizerRegistry()
    with pytest.raises(UnsupportedProviderError):
        registry.resolve("nonexistent", SchemaVersion(1, 0))


def test_resolve_known_provider_incompatible_major_raises() -> None:
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("okta", SchemaVersion(1, 0)))

    with pytest.raises(UnsupportedVersionError):
        registry.resolve("okta", SchemaVersion(2, 0))


def test_resolve_ambiguous_when_two_compatible_versions_registered() -> None:
    """Two normalizers registered for the same provider+major (e.g. 1.0
    and 1.2, both minor bumps of major=1) are both compatible with a
    request for 1.0 — the framework must not silently guess."""
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("okta", SchemaVersion(1, 0)))
    registry.register(FakeNormalizer("okta", SchemaVersion(1, 2)))

    with pytest.raises(AmbiguousNormalizerSelectionError) as exc_info:
        registry.resolve("okta", SchemaVersion(1, 0))

    assert exc_info.value.provider == "okta"
    assert len(exc_info.value.candidate_versions) == 2


def test_ambiguity_does_not_occur_across_different_majors() -> None:
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("okta", SchemaVersion(1, 0)))
    registry.register(FakeNormalizer("okta", SchemaVersion(2, 0)))

    resolved = registry.resolve("okta", SchemaVersion(1, 5))

    assert resolved.schema_version == SchemaVersion(1, 0)
