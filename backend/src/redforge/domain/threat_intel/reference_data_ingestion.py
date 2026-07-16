"""ReferenceDataIngestionRecord aggregate root — M22 Phase 1.

The single aggregate in M22 Phase 1. Backs the `stix_ingestion_log`
table and exists specifically to close the idempotency-gate gap the
Hardening Review identified: every write to a global reference table
(attack_tactics, attack_techniques, attack_technique_relationships,
vulnerabilities) must be traceable to exactly one durable ingestion
record keyed by (source_system, external_id) for GLOBAL scope, so a
concurrent or repeated admin load can never silently double-count or
diverge from what is actually stored.

Invariant enforced here (not just at the database layer): a GLOBAL-scope
record must never carry an `organization_id`; a TENANT-scope record
(reserved for M22 Phase 2 per-org TAXII ingestion) must always carry
one. This is the exact global/tenant conflation defect the Hardening
Review's Database Review (Part 3) flagged against a naive single
unique-index design.
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.threat_intel.reference_data_events import (
    ReferenceDataDomainEvent,
    ReferenceDataObjectIngested,
)
from redforge.domain.threat_intel.reference_data_exceptions import (
    InvalidIngestionScopeError,
)
from redforge.domain.threat_intel.reference_data_value_objects import (
    IngestionScope,
    ReferenceDataSource,
)


class ReferenceDataIngestionRecord:
    """Aggregate root recording one idempotent global-catalog ingestion.

    Invariants:
    - GLOBAL scope implies `organization_id is None`.
    - TENANT scope implies `organization_id is not None`.
    - Represents the CURRENT ingestion fact for one external object, not
      a full history: the application service only ever calls
      `record()` when the incoming content's hash differs from what is
      already stored (or nothing is stored yet) — an unchanged
      re-submission is a pure no-op that never reaches this aggregate at
      all. When the upstream object's content genuinely changes, a new
      record with the new `content_hash` replaces the stored one for
      that (source_system, external_id, scope) key.
    """

    __slots__ = (
        "_batch_id",
        "_content_hash",
        "_events",
        "_external_id",
        "_id",
        "_ingested_at",
        "_object_type",
        "_organization_id",
        "_scope",
        "_source_system",
    )

    def __init__(
        self,
        *,
        id: str,
        source_system: ReferenceDataSource,
        scope: IngestionScope,
        organization_id: str | None,
        object_type: str,
        external_id: str,
        content_hash: str,
        ingested_at: datetime,
        batch_id: str | None,
    ) -> None:
        self._validate_scope(scope, organization_id)
        self._id = id
        self._source_system = source_system
        self._scope = scope
        self._organization_id = organization_id
        self._object_type = object_type
        self._external_id = external_id
        self._content_hash = content_hash
        self._ingested_at = ingested_at
        self._batch_id = batch_id
        self._events: list[ReferenceDataDomainEvent] = []

    @staticmethod
    def _validate_scope(scope: IngestionScope, organization_id: str | None) -> None:
        if scope is IngestionScope.GLOBAL and organization_id is not None:
            raise InvalidIngestionScopeError(
                "GLOBAL-scope ingestion records must not carry an organization_id "
                f"(got {organization_id!r})"
            )
        if scope is IngestionScope.TENANT and organization_id is None:
            raise InvalidIngestionScopeError(
                "TENANT-scope ingestion records must carry an organization_id"
            )

    # ── Read accessors ──────────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self._id

    @property
    def source_system(self) -> ReferenceDataSource:
        return self._source_system

    @property
    def scope(self) -> IngestionScope:
        return self._scope

    @property
    def organization_id(self) -> str | None:
        return self._organization_id

    @property
    def object_type(self) -> str:
        return self._object_type

    @property
    def external_id(self) -> str:
        return self._external_id

    @property
    def content_hash(self) -> str:
        return self._content_hash

    @property
    def ingested_at(self) -> datetime:
        return self._ingested_at

    @property
    def batch_id(self) -> str | None:
        return self._batch_id

    # ── Factory ──────────────────────────────────────────────────────────

    @classmethod
    def record(
        cls,
        *,
        id: str,
        source_system: ReferenceDataSource,
        object_type: str,
        external_id: str,
        content_hash: str,
        scope: IngestionScope = IngestionScope.GLOBAL,
        organization_id: str | None = None,
        batch_id: str | None = None,
        now: datetime | None = None,
    ) -> ReferenceDataIngestionRecord:
        """Record a new idempotent ingestion of one external object.

        Only the reference-data admin loading path should call this —
        never a tenant-facing code path, since every record produced
        here is either GLOBAL (Phase 1) or TENANT (reserved for Phase 2
        TAXII ingestion), and both are outside ordinary tenant CRUD.
        """
        now = now or datetime.now(UTC)
        record = cls(
            id=id,
            source_system=source_system,
            scope=scope,
            organization_id=organization_id,
            object_type=object_type,
            external_id=external_id,
            content_hash=content_hash,
            ingested_at=now,
            batch_id=batch_id,
        )
        record._events.append(
            ReferenceDataObjectIngested(
                ingestion_record_id=id,
                source_system=source_system,
                scope=scope,
                organization_id=organization_id,
                object_type=object_type,
                external_id=external_id,
                batch_id=batch_id,
                occurred_at=now,
            )
        )
        return record

    # ── Domain events ────────────────────────────────────────────────────

    def collect_events(self) -> list[ReferenceDataDomainEvent]:
        """Return and clear pending domain events."""
        events = list(self._events)
        self._events.clear()
        return events
