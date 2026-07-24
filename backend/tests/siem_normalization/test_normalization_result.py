from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_normalization.application.dtos.normalization_result import (
    BatchNormalizationResult,
    NormalizationFailure,
    NormalizationResult,
    NormalizationStatus,
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


def test_normalized_requires_canonical_event() -> None:
    with pytest.raises(ValueError, match="canonical_event"):
        NormalizationResult(status=NormalizationStatus.NORMALIZED, canonical_event=None)


def test_non_normalized_forbids_canonical_event() -> None:
    with pytest.raises(ValueError, match="canonical_event"):
        NormalizationResult(
            status=NormalizationStatus.FAILED_NORMALIZATION, canonical_event=_canonical_event()
        )


def test_normalized_with_canonical_event_is_valid() -> None:
    event = _canonical_event()
    result = NormalizationResult(status=NormalizationStatus.NORMALIZED, canonical_event=event)
    assert result.canonical_event is event


def test_normalized_cannot_carry_failed_domain_event() -> None:
    from siem_normalization.domain.services.normalization_outcome_factory import (
        build_normalization_failed,
    )
    from siem_normalization.domain.value_objects.enums import NormalizationFailureReason

    failed_event = build_normalization_failed(
        tenant_id="t-1",
        batch_fingerprint="fp-1",
        source_vendor="acme",
        reason=NormalizationFailureReason.MAPPING_ERROR,
        detail="bad payload",
        now=datetime.now(UTC),
    )
    with pytest.raises(ValueError, match="failed_domain_event"):
        NormalizationResult(
            status=NormalizationStatus.NORMALIZED,
            canonical_event=_canonical_event(),
            failed_domain_event=failed_event,
        )


def test_non_normalized_cannot_carry_normalized_domain_event() -> None:
    from siem_normalization.domain.services.normalization_outcome_factory import (
        build_events_normalized,
    )

    normalized_event = build_events_normalized(
        tenant_id="t-1",
        batch_fingerprint="fp-1",
        schema_version="1.0",
        normalized_event_count=1,
        now=datetime.now(UTC),
    )
    with pytest.raises(ValueError, match="normalized_domain_event"):
        NormalizationResult(
            status=NormalizationStatus.REJECTED,
            normalized_domain_event=normalized_event,
        )


def test_batch_result_counts_and_normalized_events() -> None:
    normalized = NormalizationResult(
        status=NormalizationStatus.NORMALIZED, canonical_event=_canonical_event()
    )
    failed = NormalizationResult(
        status=NormalizationStatus.FAILED_NORMALIZATION,
        failures=(NormalizationFailure(stage="mapping", error_type="X", message="y"),),
    )
    batch = BatchNormalizationResult(
        status=NormalizationStatus.PARTIALLY_NORMALIZED, results=(normalized, failed)
    )

    assert batch.normalized_count == 1
    assert batch.failed_count == 1
    assert batch.normalized_events == (normalized.canonical_event,)


def test_batch_result_defaults_to_empty() -> None:
    batch = BatchNormalizationResult(status=NormalizationStatus.FAILED_NORMALIZATION)
    assert batch.results == ()
    assert batch.normalized_count == 0
    assert batch.normalized_events == ()
