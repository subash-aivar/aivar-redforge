from __future__ import annotations

from datetime import UTC, datetime

import pytest

from siem_normalization.domain.events.normalization_events import (
    EventsNormalized,
    NormalizationFailed,
)
from siem_normalization.domain.exceptions.domain_exceptions import (
    EmptyBatchFingerprintError,
    EmptyFailureDetailError,
    NoNormalizedEventsError,
)
from siem_normalization.domain.services.normalization_outcome_factory import (
    build_events_normalized,
    build_normalization_failed,
)
from siem_normalization.domain.value_objects.enums import NormalizationFailureReason

NOW = datetime.now(UTC)


def test_build_events_normalized_success() -> None:
    event = build_events_normalized(
        tenant_id="t-1",
        batch_fingerprint="fp-1",
        schema_version="1.0",
        normalized_event_count=42,
        now=NOW,
    )
    assert isinstance(event, EventsNormalized)
    assert event.normalized_event_count == 42
    assert event.schema_version == "1.0"


def test_build_events_normalized_rejects_zero_count() -> None:
    with pytest.raises(NoNormalizedEventsError):
        build_events_normalized(
            tenant_id="t-1",
            batch_fingerprint="fp-1",
            schema_version="1.0",
            normalized_event_count=0,
            now=NOW,
        )


def test_build_events_normalized_rejects_blank_fingerprint() -> None:
    with pytest.raises(EmptyBatchFingerprintError):
        build_events_normalized(
            tenant_id="t-1",
            batch_fingerprint="  ",
            schema_version="1.0",
            normalized_event_count=1,
            now=NOW,
        )


def test_build_normalization_failed_never_a_silent_drop() -> None:
    event = build_normalization_failed(
        tenant_id="t-1",
        batch_fingerprint="fp-1",
        source_vendor="okta",
        reason=NormalizationFailureReason.MALFORMED_PAYLOAD,
        detail="missing required field 'actor.id'",
        now=NOW,
    )
    assert isinstance(event, NormalizationFailed)
    assert event.reason == NormalizationFailureReason.MALFORMED_PAYLOAD
    assert event.detail == "missing required field 'actor.id'"


def test_build_normalization_failed_requires_actionable_detail() -> None:
    with pytest.raises(EmptyFailureDetailError):
        build_normalization_failed(
            tenant_id="t-1",
            batch_fingerprint="fp-1",
            source_vendor="okta",
            reason=NormalizationFailureReason.MAPPING_ERROR,
            detail="   ",
            now=NOW,
        )


def test_build_normalization_failed_rejects_blank_fingerprint() -> None:
    with pytest.raises(EmptyBatchFingerprintError):
        build_normalization_failed(
            tenant_id="t-1",
            batch_fingerprint="",
            source_vendor="okta",
            reason=NormalizationFailureReason.UNSUPPORTED_SOURCE,
            detail="no normalizer registered",
            now=NOW,
        )
