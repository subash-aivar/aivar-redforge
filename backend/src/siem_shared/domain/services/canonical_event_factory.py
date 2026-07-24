"""CanonicalEventFactory — the single sanctioned way to construct a
`CanonicalEvent` (M37 §2.1).

Centralizes the defaulting behavior (`event_id` generation, fingerprint
computation, `ingested_at` defaulting to "now") that every future
normalizer will otherwise have to reimplement — the same "one factory,
not N call sites re-deriving the same defaults" reasoning already
applied throughout this platform's other aggregate factories.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now
from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
from siem_shared.domain.value_objects.event_fingerprint import EventFingerprint
from siem_shared.domain.value_objects.event_identity import EventIdentity
from siem_shared.domain.value_objects.event_metadata import EventMetadata
from siem_shared.domain.value_objects.event_timestamp import EventTimestamp
from siem_shared.domain.value_objects.tenant_context import TenantContext

if TYPE_CHECKING:
    from datetime import datetime

    from siem_shared.domain.value_objects.entity_ref import EntityRef
    from siem_shared.domain.value_objects.event_category import EventCategory
    from siem_shared.domain.value_objects.event_outcome import EventOutcome
    from siem_shared.domain.value_objects.event_severity import EventSeverity
    from siem_shared.domain.value_objects.event_source import EventSource
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


def build_canonical_event(
    tenant_id: EntityId,
    source: EventSource,
    category: EventCategory,
    outcome: EventOutcome,
    occurred_at: datetime,
    schema_version: SchemaVersion,
    *,
    event_id: EntityId | None = None,
    fingerprint: EventFingerprint | None = None,
    ingested_at: datetime | None = None,
    severity: EventSeverity | None = None,
    actor: EntityRef | None = None,
    target: EntityRef | None = None,
    attributes: Mapping[str, object] | None = None,
    raw_payload_ref: str | None = None,
) -> CanonicalEvent:
    """Construct a fully-validated `CanonicalEvent`.

    - `event_id` defaults to a freshly generated `EntityId` (ULID).
    - `fingerprint` defaults to a deterministic hash of
      (vendor, source_type, tenant_id, occurred_at) when not supplied —
      callers that already know a source-native idempotency key should
      pass it explicitly instead.
    - `ingested_at` defaults to "now" — the platform's receipt time.

    Every nested value object still runs its own construction-time
    validation; this factory adds no separate validation path of its
    own, only defaulting.
    """
    resolved_event_id = event_id if event_id is not None else EntityId.generate()
    resolved_fingerprint = (
        fingerprint
        if fingerprint is not None
        else EventFingerprint.compute(
            source.vendor, source.source_type.value, str(tenant_id), occurred_at.isoformat()
        )
    )
    resolved_ingested_at = ingested_at if ingested_at is not None else utc_now()

    return CanonicalEvent(
        identity=EventIdentity(event_id=resolved_event_id, fingerprint=resolved_fingerprint),
        tenant=TenantContext(tenant_id=tenant_id),
        timestamp=EventTimestamp(occurred_at=occurred_at, ingested_at=resolved_ingested_at),
        source=source,
        category=category,
        outcome=outcome,
        metadata=EventMetadata(
            schema_version=schema_version,
            attributes=attributes or {},
            raw_payload_ref=raw_payload_ref,
        ),
        severity=severity,
        actor=actor,
        target=target,
    )
