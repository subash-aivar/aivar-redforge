from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_storage.application.dtos.storage_plan import StoragePlan, StoragePlanIntent
from siem_storage.application.exceptions import InvalidArchivalRequestError
from siem_storage.domain.value_objects.enums import StorageTier
from siem_storage.domain.value_objects.retention import RetentionDuration

NOW = datetime.now(UTC)


def _plan(**overrides: object) -> StoragePlan:
    defaults: dict[str, object] = {
        "tenant_id": EntityId.generate(),
        "event_fingerprint": "fp-1",
        "category": "authentication",
        "tier": StorageTier.HOT,
        "intent": StoragePlanIntent.INITIAL_PLACEMENT,
        "retention_duration": RetentionDuration(days=30),
        "compression_intent": False,
        "encryption_requirement": True,
        "archival_intent": False,
        "planned_at": NOW,
    }
    defaults.update(overrides)
    return StoragePlan(**defaults)  # type: ignore[arg-type]


def test_hot_tier_plan_construction() -> None:
    plan = _plan()
    assert plan.tier == StorageTier.HOT
    assert plan.archival_intent is False


def test_cold_tier_requires_archival_intent_true() -> None:
    plan = _plan(tier=StorageTier.COLD, archival_intent=True)
    assert plan.archival_intent is True


def test_archive_tier_requires_archival_intent_true() -> None:
    plan = _plan(tier=StorageTier.ARCHIVE, archival_intent=True)
    assert plan.archival_intent is True


def test_hot_tier_with_archival_intent_true_is_invalid() -> None:
    with pytest.raises(InvalidArchivalRequestError):
        _plan(tier=StorageTier.HOT, archival_intent=True)


def test_cold_tier_with_archival_intent_false_is_invalid() -> None:
    with pytest.raises(InvalidArchivalRequestError):
        _plan(tier=StorageTier.COLD, archival_intent=False)


def test_rejects_blank_event_fingerprint() -> None:
    with pytest.raises(ValueError, match="event_fingerprint"):
        _plan(event_fingerprint="   ")


def test_plan_is_frozen() -> None:
    plan = _plan()
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.tier = StorageTier.COLD  # type: ignore[misc]
