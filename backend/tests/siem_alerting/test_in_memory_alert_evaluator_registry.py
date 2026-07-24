from __future__ import annotations

import pytest

from siem_alerting.application.exceptions import (
    AmbiguousEvaluatorSelectionError,
    DuplicateEvaluatorRegistrationError,
    UnsupportedEvaluatorError,
    UnsupportedEvaluatorVersionError,
)
from siem_alerting.application.registry.in_memory_alert_evaluator_registry import (
    InMemoryAlertEvaluatorRegistry,
)
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import FakeAlertEvaluator


def test_register_then_resolve_returns_same_evaluator() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    evaluator = FakeAlertEvaluator("rule-1", SchemaVersion(1, 0))
    registry.register(evaluator)

    assert registry.resolve("rule-1", SchemaVersion(1, 0)) is evaluator


def test_resolve_matches_compatible_minor_version() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    evaluator = FakeAlertEvaluator("rule-1", SchemaVersion(1, 3))
    registry.register(evaluator)

    assert registry.resolve("rule-1", SchemaVersion(1, 0)) is evaluator


def test_is_registered() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("rule-1", SchemaVersion(1, 0)))

    assert registry.is_registered("rule-1", SchemaVersion(1, 0)) is True
    assert registry.is_registered("rule-1", SchemaVersion(2, 0)) is False


def test_duplicate_registration_raises() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("rule-1", SchemaVersion(1, 0)))

    with pytest.raises(DuplicateEvaluatorRegistrationError):
        registry.register(FakeAlertEvaluator("rule-1", SchemaVersion(1, 0)))


def test_different_rules_do_not_conflict() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("rule-1", SchemaVersion(1, 0)))
    registry.register(FakeAlertEvaluator("rule-2", SchemaVersion(1, 0)))

    assert registry.is_registered("rule-1", SchemaVersion(1, 0))
    assert registry.is_registered("rule-2", SchemaVersion(1, 0))


def test_resolve_unknown_rule_raises() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    with pytest.raises(UnsupportedEvaluatorError):
        registry.resolve("nonexistent", SchemaVersion(1, 0))


def test_resolve_incompatible_major_raises() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("rule-1", SchemaVersion(1, 0)))

    with pytest.raises(UnsupportedEvaluatorVersionError):
        registry.resolve("rule-1", SchemaVersion(2, 0))


def test_resolve_ambiguous_when_two_compatible_versions_registered() -> None:
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("rule-1", SchemaVersion(1, 0)))
    registry.register(FakeAlertEvaluator("rule-1", SchemaVersion(1, 5)))

    with pytest.raises(AmbiguousEvaluatorSelectionError) as exc_info:
        registry.resolve("rule-1", SchemaVersion(1, 0))

    assert exc_info.value.rule_id == "rule-1"
    assert len(exc_info.value.candidate_versions) == 2
