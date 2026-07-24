from __future__ import annotations

import pytest

from siem_alerting.application.exceptions import InvalidSuppressionDecisionError
from siem_alerting.application.ports.alert_evaluation_result import AlertEvaluationResult
from siem_alerting.domain.value_objects.enums import AlertSeverity


def test_construction_no_suppress() -> None:
    result = AlertEvaluationResult(should_alert=True, severity=AlertSeverity.HIGH, reason="x")
    assert result.suppress is False
    assert result.suppression_reason is None


def test_construction_with_suppress() -> None:
    result = AlertEvaluationResult(
        should_alert=True,
        severity=AlertSeverity.LOW,
        reason="x",
        suppress=True,
        suppression_reason="known benign",
    )
    assert result.suppress is True


def test_blank_reason_rejected() -> None:
    with pytest.raises(ValueError, match="reason"):
        AlertEvaluationResult(should_alert=True, severity=AlertSeverity.HIGH, reason="  ")


def test_suppress_without_reason_rejected() -> None:
    with pytest.raises(InvalidSuppressionDecisionError):
        AlertEvaluationResult(
            should_alert=True, severity=AlertSeverity.LOW, reason="x", suppress=True
        )


def test_suppress_false_with_reason_rejected() -> None:
    with pytest.raises(InvalidSuppressionDecisionError):
        AlertEvaluationResult(
            should_alert=True,
            severity=AlertSeverity.LOW,
            reason="x",
            suppress=False,
            suppression_reason="unexpected",
        )
