from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from siem_correlation.application.dtos.correlation_result import CorrelationResult

NOW = datetime.now(UTC)


def _result(**overrides: object) -> CorrelationResult:
    defaults: dict[str, object] = {
        "session_id": "session-1",
        "correlation_rule_id": "rule-1",
        "correlated_event_ids": ("event-1", "event-2"),
        "detection_match_refs": ("rule-1:event-2",),
        "confidence": 0.8,
        "reason": "brute force pattern",
        "window_started_at": NOW,
        "window_expires_at": NOW + timedelta(minutes=15),
    }
    defaults.update(overrides)
    return CorrelationResult(**defaults)  # type: ignore[arg-type]


def test_construction() -> None:
    result = _result()
    assert result.session_id == "session-1"
    assert len(result.correlated_event_ids) == 2


def test_rejects_blank_session_id() -> None:
    with pytest.raises(ValueError, match="session_id"):
        _result(session_id="  ")


def test_rejects_blank_correlation_rule_id() -> None:
    with pytest.raises(ValueError, match="correlation_rule_id"):
        _result(correlation_rule_id="")


def test_rejects_empty_correlated_event_ids() -> None:
    with pytest.raises(ValueError, match="correlated_event_ids"):
        _result(correlated_event_ids=())


def test_rejects_confidence_out_of_range() -> None:
    with pytest.raises(ValueError, match="confidence"):
        _result(confidence=1.5)


def test_rejects_blank_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        _result(reason="   ")


def test_is_frozen() -> None:
    result = _result()
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.confidence = 0.1  # type: ignore[misc]
