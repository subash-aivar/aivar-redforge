from __future__ import annotations

import pytest

from siem_correlation.application.ports.correlation_evaluation_result import (
    CorrelationEvaluationResult,
)


def test_construction() -> None:
    result = CorrelationEvaluationResult(matched=True, confidence=0.7, reason="pattern matched")
    assert result.matched is True


def test_confidence_bounds_valid() -> None:
    CorrelationEvaluationResult(matched=False, confidence=0.0, reason="x")
    CorrelationEvaluationResult(matched=True, confidence=1.0, reason="x")


def test_confidence_above_one_rejected() -> None:
    with pytest.raises(ValueError, match="confidence"):
        CorrelationEvaluationResult(matched=True, confidence=1.1, reason="x")


def test_confidence_negative_rejected() -> None:
    with pytest.raises(ValueError, match="confidence"):
        CorrelationEvaluationResult(matched=True, confidence=-0.1, reason="x")


def test_blank_reason_rejected() -> None:
    with pytest.raises(ValueError, match="reason"):
        CorrelationEvaluationResult(matched=True, confidence=0.5, reason="  ")
