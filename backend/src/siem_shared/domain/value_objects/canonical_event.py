"""CanonicalEvent — the single platform event format (M37 §2.1).

Every source-specific event is transformed by `siem_normalization` into
one `CanonicalEvent` shape before anything downstream ever sees it —
"no bounded context downstream of normalization understands a vendor-
specific schema" is the architectural non-negotiable of the whole SIEM.

Immutable, append-only — same immutability principle as
`docs/adr/0003-evidence-immutability.md` already established for
Evidence. There are no mutator methods on this type by design: a
CanonicalEvent is never edited once constructed, only ever replaced by
a newer one (reprocessing/backfill is a projection concern, per M37
§2.3, never a mutation of a stored event).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from redforge.shared.identifiers import EntityId
from siem_shared.domain.value_objects.entity_ref import EntityRef, EntityRefType
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_fingerprint import EventFingerprint
from siem_shared.domain.value_objects.event_identity import EventIdentity
from siem_shared.domain.value_objects.event_metadata import EventMetadata
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_severity import EventSeverity
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType
from siem_shared.domain.value_objects.event_timestamp import EventTimestamp
from siem_shared.domain.value_objects.schema_version import SchemaVersion
from siem_shared.domain.value_objects.tenant_context import TenantContext


def _entity_ref_to_dict(ref: EntityRef) -> dict[str, Any]:
    return {
        "entity_type": ref.entity_type.value,
        "raw_identifier": ref.raw_identifier,
        "entity_id": str(ref.entity_id) if ref.entity_id is not None else None,
    }


def _entity_ref_from_dict(data: dict[str, Any]) -> EntityRef:
    entity_id = data.get("entity_id")
    return EntityRef(
        entity_type=EntityRefType(data["entity_type"]),
        raw_identifier=data["raw_identifier"],
        entity_id=EntityId.from_string(entity_id) if entity_id is not None else None,
    )


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    identity: EventIdentity
    tenant: TenantContext
    timestamp: EventTimestamp
    source: EventSource
    category: EventCategory
    outcome: EventOutcome
    metadata: EventMetadata
    severity: EventSeverity | None = None
    actor: EntityRef | None = None
    target: EntityRef | None = None

    def to_dict(self) -> dict[str, Any]:
        """The serialization contract every downstream consumer relies
        on — a plain, JSON-safe `dict` that round-trips through
        `from_dict` without loss."""
        return {
            "event_id": str(self.identity.event_id),
            "fingerprint": str(self.identity.fingerprint),
            "tenant_id": str(self.tenant.tenant_id),
            "occurred_at": self.timestamp.occurred_at.isoformat(),
            "ingested_at": self.timestamp.ingested_at.isoformat(),
            "source": {
                "source_type": self.source.source_type.value,
                "vendor": self.source.vendor,
                "source_connector_id": (
                    str(self.source.source_connector_id)
                    if self.source.source_connector_id is not None
                    else None
                ),
            },
            "category": self.category.value,
            "severity": self.severity.value if self.severity is not None else None,
            "actor": _entity_ref_to_dict(self.actor) if self.actor is not None else None,
            "target": _entity_ref_to_dict(self.target) if self.target is not None else None,
            "outcome": self.outcome.value,
            "schema_version": str(self.metadata.schema_version),
            "attributes": self.metadata.attributes_as_dict(),
            "raw_payload_ref": self.metadata.raw_payload_ref,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CanonicalEvent:
        """Reconstruct a `CanonicalEvent` from `to_dict`'s output. Every
        nested value object re-runs its own construction-time
        validation, so a tampered/malformed payload fails the same way
        a bad direct construction would — there is no separate,
        weaker deserialization validation path."""
        source_data = data["source"]
        actor_data = data.get("actor")
        target_data = data.get("target")
        severity = data.get("severity")

        return cls(
            identity=EventIdentity(
                event_id=EntityId.from_string(data["event_id"]),
                fingerprint=EventFingerprint(data["fingerprint"]),
            ),
            tenant=TenantContext(tenant_id=EntityId.from_string(data["tenant_id"])),
            timestamp=EventTimestamp(
                occurred_at=_parse_iso(data["occurred_at"]),
                ingested_at=_parse_iso(data["ingested_at"]),
            ),
            source=EventSource(
                source_type=EventSourceType(source_data["source_type"]),
                vendor=source_data["vendor"],
                source_connector_id=(
                    EntityId.from_string(source_data["source_connector_id"])
                    if source_data.get("source_connector_id") is not None
                    else None
                ),
            ),
            category=EventCategory(data["category"]),
            outcome=EventOutcome(data["outcome"]),
            metadata=EventMetadata(
                schema_version=SchemaVersion.parse(data["schema_version"]),
                attributes=data.get("attributes") or {},
                raw_payload_ref=data.get("raw_payload_ref"),
            ),
            severity=EventSeverity(severity) if severity is not None else None,
            actor=_entity_ref_from_dict(actor_data) if actor_data is not None else None,
            target=_entity_ref_from_dict(target_data) if target_data is not None else None,
        )


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)
