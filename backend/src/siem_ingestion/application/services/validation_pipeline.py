"""The ingestion pipeline's validation stages (M43C §3).

Every stage is a pure function that either returns successfully or
raises one of `siem_ingestion.application.exceptions`'s typed domain
errors — never a bare `ValueError`. `IngestionApplicationService`
orchestrates these stages and translates a raised error into a
`ValidationFailure` entry on the returned acceptance result; no
exception is ever allowed to propagate out of the service to a caller
for an *expected* validation failure.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING

from siem_ingestion.application.exceptions import (
    InvalidEventCategoryError,
    InvalidEventOutcomeError,
    InvalidEventSeverityError,
    MissingRequiredFieldError,
    PayloadTooLargeError,
    SchemaVersionUnsupportedError,
    TenantContextMismatchError,
    TimestampOutOfSanityRangeError,
)
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_severity import EventSeverity

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_ingestion.application.commands.ingestion_commands import SubmitEventCommand
    from siem_shared.domain.value_objects.schema_version import SchemaVersion

MAX_PAYLOAD_BYTES = 262_144  # 256 KiB
MAX_PAST_AGE = timedelta(days=3650)  # 10 years


def validate_required_fields(cmd: SubmitEventCommand) -> None:
    if not cmd.vendor.strip():
        raise MissingRequiredFieldError("vendor")
    if not cmd.category_raw.strip():
        raise MissingRequiredFieldError("category_raw")
    if not cmd.outcome_raw.strip():
        raise MissingRequiredFieldError("outcome_raw")
    if not cmd.schema_version_raw.strip():
        raise MissingRequiredFieldError("schema_version_raw")


def validate_batch_tenant_consistency(batch_tenant_id: EntityId, event_tenant_id: EntityId) -> None:
    """A batch must never silently mix events from multiple tenants
    (M37 §4's tenant-isolation discipline applies at admission time,
    not only at storage time)."""
    if batch_tenant_id != event_tenant_id:
        raise TenantContextMismatchError(batch_tenant_id, event_tenant_id)


def validate_timestamp_sanity(
    occurred_at: datetime,
    now: datetime,
    *,
    max_past_age: timedelta = MAX_PAST_AGE,
) -> None:
    """Timezone-awareness and (implicitly, via `ingested_at = now`)
    future-dating are already enforced by `EventTimestamp` itself
    (M43B) when the `CanonicalEvent` is built — `ingested_at` is always
    "now" at ingestion time, so `EventTimestamp`'s own
    `ingested_at >= occurred_at` invariant already rejects any
    future-dated `occurred_at`. Duplicating a separate future-skew
    check here would only create a second, inconsistent threshold. This
    stage adds the one admission-time business check that invariant
    does *not* cover: an implausibly old `occurred_at`, specific to
    ingestion, not a CEM invariant.
    """
    if occurred_at.tzinfo is None:
        raise TimestampOutOfSanityRangeError("occurred_at must be timezone-aware")
    if occurred_at < now - max_past_age:
        raise TimestampOutOfSanityRangeError(f"occurred_at is older than {max_past_age}")


def validate_event_category(category_raw: str) -> EventCategory:
    try:
        return EventCategory(category_raw)
    except ValueError:
        raise InvalidEventCategoryError(category_raw) from None


def validate_event_outcome(outcome_raw: str) -> EventOutcome:
    try:
        return EventOutcome(outcome_raw)
    except ValueError:
        raise InvalidEventOutcomeError(outcome_raw) from None


def validate_event_severity(severity_raw: str | None) -> EventSeverity | None:
    if severity_raw is None:
        return None
    try:
        return EventSeverity(severity_raw)
    except ValueError:
        raise InvalidEventSeverityError(severity_raw) from None


def validate_payload_size(
    attributes: Mapping[str, object], *, max_bytes: int = MAX_PAYLOAD_BYTES
) -> None:
    size_bytes = len(json.dumps(attributes, default=str).encode("utf-8"))
    if size_bytes > max_bytes:
        raise PayloadTooLargeError(size_bytes, max_bytes)


def validate_schema_compatibility(schema_version: SchemaVersion, supported: SchemaVersion) -> None:
    if not schema_version.is_compatible_with(supported):
        raise SchemaVersionUnsupportedError(schema_version, supported)
