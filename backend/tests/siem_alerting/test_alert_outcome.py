from __future__ import annotations

import pytest

from siem_alerting.application.dtos.alert_outcome import (
    AlertFailure,
    AlertOutcome,
    AlertOutcomeStatus,
    BatchAlertResult,
)


def test_created_requires_alert_id() -> None:
    with pytest.raises(ValueError, match="alert_id"):
        AlertOutcome(status=AlertOutcomeStatus.CREATED, alert_id=None)


def test_rejected_forbids_alert_id() -> None:
    with pytest.raises(ValueError, match="alert_id"):
        AlertOutcome(status=AlertOutcomeStatus.REJECTED, alert_id="alert-1")


def test_suppressed_requires_alert_id() -> None:
    with pytest.raises(ValueError, match="alert_id"):
        AlertOutcome(status=AlertOutcomeStatus.SUPPRESSED, alert_id=None)


def test_deduplicated_requires_alert_id() -> None:
    with pytest.raises(ValueError, match="alert_id"):
        AlertOutcome(status=AlertOutcomeStatus.DEDUPLICATED, alert_id=None)


def test_original_alert_id_only_valid_for_deduplicated() -> None:
    with pytest.raises(ValueError, match="original_alert_id"):
        AlertOutcome(
            status=AlertOutcomeStatus.CREATED, alert_id="alert-1", original_alert_id="alert-0"
        )


def test_deduplicated_with_original_alert_id_is_valid() -> None:
    outcome = AlertOutcome(
        status=AlertOutcomeStatus.DEDUPLICATED, alert_id="alert-2", original_alert_id="alert-1"
    )
    assert outcome.original_alert_id == "alert-1"


def test_batch_result_counts() -> None:
    created = AlertOutcome(status=AlertOutcomeStatus.CREATED, alert_id="a1")
    deduped = AlertOutcome(
        status=AlertOutcomeStatus.DEDUPLICATED, alert_id="a2", original_alert_id="a1"
    )
    failed = AlertOutcome(
        status=AlertOutcomeStatus.FAILED,
        failures=(AlertFailure(stage="execution", error_type="X", message="y"),),
    )
    batch = BatchAlertResult(
        status=AlertOutcomeStatus.PARTIALLY_SUCCEEDED, outcomes=(created, deduped, failed)
    )

    assert batch.created_count == 2
    assert batch.failed_count == 1


def test_batch_result_defaults_to_empty() -> None:
    batch = BatchAlertResult(status=AlertOutcomeStatus.FAILED)
    assert batch.outcomes == ()
    assert batch.created_count == 0
