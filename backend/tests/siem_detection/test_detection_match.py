from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from siem_detection.application.dtos.detection_match import DetectionMatch
from siem_shared.domain.value_objects.event_severity import EventSeverity

NOW = datetime.now(UTC)


def _match(**overrides: object) -> DetectionMatch:
    defaults: dict[str, object] = {
        "rule_id": "rule-1",
        "event_id": "event-1",
        "matched_at": NOW,
        "severity": EventSeverity.HIGH,
        "confidence": 0.9,
        "reason": "brute force pattern matched",
    }
    defaults.update(overrides)
    return DetectionMatch(**defaults)  # type: ignore[arg-type]


def test_construction() -> None:
    match = _match()
    assert match.rule_id == "rule-1"
    assert match.severity == EventSeverity.HIGH


def test_rejects_blank_rule_id() -> None:
    with pytest.raises(ValueError, match="rule_id"):
        _match(rule_id="  ")


def test_rejects_blank_event_id() -> None:
    with pytest.raises(ValueError, match="event_id"):
        _match(event_id="")


def test_rejects_confidence_out_of_range() -> None:
    with pytest.raises(ValueError, match="confidence"):
        _match(confidence=1.5)


def test_rejects_blank_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        _match(reason="   ")


def test_is_frozen() -> None:
    match = _match()
    with pytest.raises(dataclasses.FrozenInstanceError):
        match.confidence = 0.1  # type: ignore[misc]
