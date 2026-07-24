from __future__ import annotations

import pytest

from siem_detection.application.ports.detection_evaluation_result import (
    DetectionEvaluationResult,
)
from siem_shared.domain.value_objects.event_severity import EventSeverity


def test_construction() -> None:
    result = DetectionEvaluationResult(
        matched=True, severity=EventSeverity.HIGH, confidence=0.8, reason="matched pattern"
    )
    assert result.matched is True


def test_confidence_zero_and_one_are_valid_bounds() -> None:
    DetectionEvaluationResult(matched=False, severity=EventSeverity.LOW, confidence=0.0, reason="x")
    DetectionEvaluationResult(matched=True, severity=EventSeverity.LOW, confidence=1.0, reason="x")


def test_confidence_above_one_rejected() -> None:
    with pytest.raises(ValueError, match="confidence"):
        DetectionEvaluationResult(
            matched=True, severity=EventSeverity.LOW, confidence=1.1, reason="x"
        )


def test_confidence_negative_rejected() -> None:
    with pytest.raises(ValueError, match="confidence"):
        DetectionEvaluationResult(
            matched=True, severity=EventSeverity.LOW, confidence=-0.1, reason="x"
        )


def test_blank_reason_rejected() -> None:
    with pytest.raises(ValueError, match="reason"):
        DetectionEvaluationResult(matched=True, severity=EventSeverity.LOW, confidence=0.5, reason="  ")
