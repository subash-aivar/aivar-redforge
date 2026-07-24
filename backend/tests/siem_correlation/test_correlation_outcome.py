from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from siem_correlation.application.dtos.correlation_outcome import (
    BatchCorrelationResult,
    CorrelationFailure,
    CorrelationOutcome,
    CorrelationStatus,
)
from siem_correlation.application.dtos.correlation_result import CorrelationResult

NOW = datetime.now(UTC)


def _result() -> CorrelationResult:
    return CorrelationResult(
        session_id="session-1",
        correlation_rule_id="rule-1",
        correlated_event_ids=("event-1",),
        detection_match_refs=("rule-1:event-1",),
        confidence=0.8,
        reason="matched",
        window_started_at=NOW,
        window_expires_at=NOW + timedelta(minutes=15),
    )


def test_outcome_result_requires_succeeded_status() -> None:
    with pytest.raises(ValueError, match="SUCCEEDED"):
        CorrelationOutcome(
            correlation_rule_id="rule-1", status=CorrelationStatus.FAILED, result=_result()
        )


def test_outcome_succeeded_without_result_is_valid() -> None:
    outcome = CorrelationOutcome(
        correlation_rule_id="rule-1", status=CorrelationStatus.SUCCEEDED, result=None
    )
    assert outcome.result is None


def test_outcome_succeeded_with_result_is_valid() -> None:
    result = _result()
    outcome = CorrelationOutcome(
        correlation_rule_id="rule-1", status=CorrelationStatus.SUCCEEDED, result=result
    )
    assert outcome.result is result


def test_batch_result_counts_and_matches() -> None:
    result = _result()
    succeeded = CorrelationOutcome(
        correlation_rule_id="rule-1", status=CorrelationStatus.SUCCEEDED, result=result
    )
    failed = CorrelationOutcome(
        correlation_rule_id="rule-2",
        status=CorrelationStatus.FAILED,
        failures=(CorrelationFailure(stage="execution", error_type="X", message="y"),),
    )
    batch = BatchCorrelationResult(
        status=CorrelationStatus.PARTIALLY_SUCCEEDED, outcomes=(succeeded, failed)
    )

    assert batch.succeeded_count == 1
    assert batch.failed_count == 1
    assert batch.matches == (result,)


def test_batch_result_defaults_to_empty() -> None:
    batch = BatchCorrelationResult(status=CorrelationStatus.FAILED)
    assert batch.outcomes == ()
    assert batch.matches == ()
