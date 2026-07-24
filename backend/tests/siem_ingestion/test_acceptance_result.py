from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_ingestion.application.dtos.acceptance_result import (
    AcceptanceStatus,
    BatchAcceptanceResult,
    EventAcceptanceResult,
    ValidationFailure,
)
from siem_shared.domain.services.canonical_event_factory import build_canonical_event
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType
from siem_shared.domain.value_objects.schema_version import SchemaVersion


def _canonical_event():
    return build_canonical_event(
        tenant_id=EntityId.generate(),
        source=EventSource(source_type=EventSourceType.CLOUD, vendor="aws"),
        category=EventCategory.CLOUD_API,
        outcome=EventOutcome.SUCCESS,
        occurred_at=datetime.now(UTC),
        schema_version=SchemaVersion(1, 0),
    )


def test_accepted_requires_canonical_event() -> None:
    with pytest.raises(ValueError, match="canonical_event"):
        EventAcceptanceResult(status=AcceptanceStatus.ACCEPTED, canonical_event=None)


def test_non_accepted_forbids_canonical_event() -> None:
    with pytest.raises(ValueError, match="canonical_event"):
        EventAcceptanceResult(
            status=AcceptanceStatus.VALIDATION_FAILED, canonical_event=_canonical_event()
        )


def test_accepted_with_canonical_event_is_valid() -> None:
    event = _canonical_event()
    result = EventAcceptanceResult(status=AcceptanceStatus.ACCEPTED, canonical_event=event)
    assert result.canonical_event is event


def test_validation_failed_with_failures_is_valid() -> None:
    result = EventAcceptanceResult(
        status=AcceptanceStatus.VALIDATION_FAILED,
        failures=(ValidationFailure(stage="x", error_type="Y", message="z"),),
    )
    assert len(result.failures) == 1


def test_batch_result_accepted_and_rejected_counts() -> None:
    accepted = EventAcceptanceResult(
        status=AcceptanceStatus.ACCEPTED, canonical_event=_canonical_event()
    )
    rejected = EventAcceptanceResult(status=AcceptanceStatus.VALIDATION_FAILED)
    batch = BatchAcceptanceResult(
        status=AcceptanceStatus.PARTIALLY_ACCEPTED, results=(accepted, rejected)
    )
    assert batch.accepted_count == 1
    assert batch.rejected_count == 1
    assert batch.accepted_events == (accepted.canonical_event,)


def test_batch_result_defaults_to_empty_results() -> None:
    batch = BatchAcceptanceResult(status=AcceptanceStatus.RATE_LIMITED)
    assert batch.results == ()
    assert batch.accepted_count == 0
    assert batch.rejected_count == 0
    assert batch.accepted_events == ()
