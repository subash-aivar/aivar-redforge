from __future__ import annotations

from datetime import UTC, datetime

import pytest

from siem_detection.application.dtos.detection_match import DetectionMatch
from siem_detection.application.dtos.detection_result import (
    BatchDetectionResult,
    DetectionFailure,
    DetectionStatus,
    EventDetectionResult,
    RuleEvaluationOutcome,
)
from siem_shared.domain.value_objects.event_severity import EventSeverity


def _match() -> DetectionMatch:
    return DetectionMatch(
        rule_id="rule-1",
        event_id="event-1",
        matched_at=datetime.now(UTC),
        severity=EventSeverity.HIGH,
        confidence=0.9,
        reason="matched",
    )


def test_outcome_match_requires_succeeded_status() -> None:
    with pytest.raises(ValueError, match="SUCCEEDED"):
        RuleEvaluationOutcome(rule_id="rule-1", status=DetectionStatus.FAILED, match=_match())


def test_outcome_succeeded_without_match_is_valid() -> None:
    outcome = RuleEvaluationOutcome(rule_id="rule-1", status=DetectionStatus.SUCCEEDED, match=None)
    assert outcome.match is None


def test_outcome_succeeded_with_match_is_valid() -> None:
    match = _match()
    outcome = RuleEvaluationOutcome(rule_id="rule-1", status=DetectionStatus.SUCCEEDED, match=match)
    assert outcome.match is match


def test_event_result_rejected_requires_failures() -> None:
    with pytest.raises(ValueError, match="failures"):
        EventDetectionResult(status=DetectionStatus.EVALUATION_REJECTED, event_id="e1")


def test_event_result_rejected_forbids_outcomes() -> None:
    outcome = RuleEvaluationOutcome(rule_id="rule-1", status=DetectionStatus.RULE_DISABLED)
    with pytest.raises(ValueError, match="no outcomes"):
        EventDetectionResult(
            status=DetectionStatus.EVALUATION_REJECTED,
            event_id="e1",
            outcomes=(outcome,),
            failures=(DetectionFailure(stage="x", error_type="Y", message="z"),),
        )


def test_event_result_matches_property_filters_only_matched_outcomes() -> None:
    match = _match()
    outcomes = (
        RuleEvaluationOutcome(rule_id="rule-1", status=DetectionStatus.SUCCEEDED, match=match),
        RuleEvaluationOutcome(rule_id="rule-2", status=DetectionStatus.SUCCEEDED, match=None),
        RuleEvaluationOutcome(rule_id="rule-3", status=DetectionStatus.RULE_DISABLED),
    )
    result = EventDetectionResult(status=DetectionStatus.SUCCEEDED, event_id="e1", outcomes=outcomes)
    assert result.matches == (match,)


def test_batch_result_counts_and_matches() -> None:
    match = _match()
    succeeded = EventDetectionResult(
        status=DetectionStatus.SUCCEEDED,
        event_id="e1",
        outcomes=(RuleEvaluationOutcome(rule_id="rule-1", status=DetectionStatus.SUCCEEDED, match=match),),
    )
    failed = EventDetectionResult(
        status=DetectionStatus.FAILED,
        event_id="e2",
        outcomes=(
            RuleEvaluationOutcome(
                rule_id="rule-1",
                status=DetectionStatus.FAILED,
                failures=(DetectionFailure(stage="execution", error_type="X", message="y"),),
            ),
        ),
    )
    batch = BatchDetectionResult(
        status=DetectionStatus.PARTIALLY_SUCCEEDED, results=(succeeded, failed)
    )

    assert batch.succeeded_count == 1
    assert batch.failed_count == 1
    assert batch.matches == (match,)


def test_batch_result_defaults_to_empty() -> None:
    batch = BatchDetectionResult(status=DetectionStatus.FAILED)
    assert batch.results == ()
    assert batch.matches == ()
