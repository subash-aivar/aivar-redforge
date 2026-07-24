"""StoragePlan — planning metadata only (M43E §5).

A `StoragePlan` never causes physical storage movement, compression, or
encryption to happen — it *records the intent* a future physical
storage implementation (M42 Phase 5+, explicitly out of this
milestone's scope) must honor. Nothing in this module performs I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from siem_storage.application.exceptions import InvalidArchivalRequestError
from siem_storage.domain.value_objects.enums import StorageTier

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_storage.domain.value_objects.retention import RetentionDuration

_ARCHIVAL_TIERS = frozenset({StorageTier.COLD, StorageTier.ARCHIVE})


class StoragePlanIntent(StrEnum):
    """What kind of planning decision this `StoragePlan` represents —
    distinct from `tier` (*where*), this is *why* the plan exists."""

    INITIAL_PLACEMENT = "initial_placement"
    TIER_TRANSITION = "tier_transition"
    RETENTION_EXPIRY = "retention_expiry"
    ARCHIVAL = "archival"


@dataclass(frozen=True, slots=True)
class StoragePlan:
    tenant_id: EntityId
    event_fingerprint: str
    category: str
    tier: StorageTier
    intent: StoragePlanIntent
    retention_duration: RetentionDuration
    compression_intent: bool
    encryption_requirement: bool
    archival_intent: bool
    planned_at: datetime

    def __post_init__(self) -> None:
        if not self.event_fingerprint.strip():
            raise ValueError("StoragePlan.event_fingerprint must be a non-empty string")
        expected_archival_intent = self.tier in _ARCHIVAL_TIERS
        if self.archival_intent != expected_archival_intent:
            raise InvalidArchivalRequestError(
                f"archival_intent={self.archival_intent} is inconsistent with tier={self.tier} "
                f"(archival_intent must be {expected_archival_intent} for this tier)"
            )
