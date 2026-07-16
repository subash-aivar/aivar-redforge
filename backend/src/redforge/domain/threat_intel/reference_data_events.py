"""Domain events for the Threat Intelligence Reference Data
sub-context — M22 Phase 1.

Domain events are collected by the `ReferenceDataIngestionRecord`
aggregate and dispatched by the application service — never triggered
directly by infrastructure code. Follows the exact frozen-dataclass +
union-alias pattern established by `domain/investigations/events.py`
(M21).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.threat_intel.reference_data_value_objects import (
        IngestionScope,
        ReferenceDataSource,
    )


@dataclass(frozen=True, slots=True)
class ReferenceDataObjectIngested:
    """Fired when a single global reference-data object (an ATT&CK
    tactic, technique, technique relationship, or vulnerability record)
    is durably recorded via the idempotency gate — either the first
    time it is ingested, or again when its content has changed since
    the last ingestion.

    Not fired on a no-op re-ingestion of unchanged content — see
    `ReferenceDataIngestionRecord.record()`.
    """

    ingestion_record_id: str
    source_system: ReferenceDataSource
    scope: IngestionScope
    organization_id: str | None
    object_type: str
    external_id: str
    batch_id: str | None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


ReferenceDataDomainEvent = ReferenceDataObjectIngested
