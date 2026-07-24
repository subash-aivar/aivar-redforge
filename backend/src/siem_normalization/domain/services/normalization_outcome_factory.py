"""Domain service constructing normalization outcome events.

`siem_normalization` owns no aggregate (M37 §2.2 lists none for this
context — it is pure, stateless transformation logic). Its domain
behavior is instead expressed as invariants on the events it is
allowed to raise: a success must carry at least one normalized event,
and a failure must carry an actionable, non-empty diagnostic (M37 §2.4
— failures are first-class, never silent drops).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_normalization.domain.events.normalization_events import (
    EventsNormalized,
    NormalizationFailed,
)
from siem_normalization.domain.exceptions.domain_exceptions import (
    EmptyBatchFingerprintError,
    EmptyFailureDetailError,
    NoNormalizedEventsError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from siem_normalization.domain.value_objects.enums import NormalizationFailureReason


def build_events_normalized(
    tenant_id: str,
    batch_fingerprint: str,
    schema_version: str,
    normalized_event_count: int,
    now: datetime,
) -> EventsNormalized:
    if not batch_fingerprint.strip():
        raise EmptyBatchFingerprintError()
    if normalized_event_count <= 0:
        raise NoNormalizedEventsError()
    return EventsNormalized(
        tenant_id=tenant_id,
        aggregate_id=batch_fingerprint,
        aggregate_type="IngestedEventBatch",
        occurred_at=now,
        batch_fingerprint=batch_fingerprint,
        schema_version=schema_version,
        normalized_event_count=normalized_event_count,
    )


def build_normalization_failed(
    tenant_id: str,
    batch_fingerprint: str,
    source_vendor: str,
    reason: NormalizationFailureReason,
    detail: str,
    now: datetime,
) -> NormalizationFailed:
    if not batch_fingerprint.strip():
        raise EmptyBatchFingerprintError()
    if not detail.strip():
        raise EmptyFailureDetailError()
    return NormalizationFailed(
        tenant_id=tenant_id,
        aggregate_id=batch_fingerprint,
        aggregate_type="IngestedEventBatch",
        occurred_at=now,
        batch_fingerprint=batch_fingerprint,
        source_vendor=source_vendor,
        reason=reason,
        detail=detail.strip(),
    )
