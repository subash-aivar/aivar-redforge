from __future__ import annotations

import pytest

from siem_investigation.application.dtos.investigation_outcome import (
    BatchInvestigationResult,
    InvestigationFailure,
    InvestigationOutcome,
    InvestigationOutcomeStatus,
)


def test_opened_requires_timeline_id() -> None:
    with pytest.raises(ValueError, match="timeline_id"):
        InvestigationOutcome(status=InvestigationOutcomeStatus.OPENED, timeline_id=None)


def test_updated_requires_timeline_id() -> None:
    with pytest.raises(ValueError, match="timeline_id"):
        InvestigationOutcome(status=InvestigationOutcomeStatus.UPDATED, timeline_id=None)


def test_rejected_forbids_timeline_id() -> None:
    with pytest.raises(ValueError, match="timeline_id"):
        InvestigationOutcome(status=InvestigationOutcomeStatus.REJECTED, timeline_id="t1")


def test_valid_opened_outcome() -> None:
    outcome = InvestigationOutcome(
        status=InvestigationOutcomeStatus.OPENED, timeline_id="t1", entry_count=1
    )
    assert outcome.timeline_id == "t1"


def test_batch_result_counts() -> None:
    opened = InvestigationOutcome(status=InvestigationOutcomeStatus.OPENED, timeline_id="t1")
    updated = InvestigationOutcome(status=InvestigationOutcomeStatus.UPDATED, timeline_id="t1")
    failed = InvestigationOutcome(
        status=InvestigationOutcomeStatus.FAILED,
        failures=(InvestigationFailure(stage="execution", error_type="X", message="y"),),
    )
    batch = BatchInvestigationResult(
        status=InvestigationOutcomeStatus.PARTIALLY_SUCCEEDED,
        outcomes=(opened, updated, failed),
    )

    assert batch.opened_or_updated_count == 2
    assert batch.failed_count == 1


def test_batch_result_defaults_to_empty() -> None:
    batch = BatchInvestigationResult(status=InvestigationOutcomeStatus.FAILED)
    assert batch.outcomes == ()
    assert batch.opened_or_updated_count == 0
