"""IStorageStrategy — the one open extension point for tier-specific
planning behavior (M43E §3), mirroring the same registry/plugin,
additive, open-closed shape M37 §17 already commits every SIEM
sub-context to.

No concrete implementation lives in this milestone — this is the
contract a future tier-specific planner must satisfy. Producing a
`StoragePlan` from these interfaces is `StorageApplicationService`'s
job (M43E §2); a strategy only decides that plan's tier-specific
content (compression/encryption/archival intent), never performs I/O.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_storage.application.dtos.storage_plan import StoragePlan, StoragePlanIntent
    from siem_storage.domain.value_objects.enums import StorageTier
    from siem_storage.domain.value_objects.retention import RetentionPolicy


class IStorageStrategy(Protocol):
    """Takes identity primitives, not a full `CanonicalEvent` — a
    lifecycle-transition plan (`ArchiveEventCommand`) only ever has an
    event's fingerprint/category on hand, never its full payload, so
    this signature stays uniform across both initial-placement and
    transition planning rather than needing two incompatible shapes."""

    @property
    def tier(self) -> StorageTier: ...

    def plan(
        self,
        tenant_id: EntityId,
        event_fingerprint: str,
        category: str,
        retention_policy: RetentionPolicy,
        intent: StoragePlanIntent,
        now: datetime,
    ) -> StoragePlan: ...
