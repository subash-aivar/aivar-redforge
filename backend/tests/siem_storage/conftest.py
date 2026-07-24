from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from redforge.shared.identifiers import EntityId
from siem_shared.domain.services.canonical_event_factory import build_canonical_event
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType
from siem_shared.domain.value_objects.schema_version import SchemaVersion
from siem_storage.domain.value_objects.enums import StorageRole, StorageTier
from siem_storage.domain.value_objects.retention import RetentionDuration, RetentionPolicy

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId as EntityIdType
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
    from siem_storage.application.dtos.storage_plan import StoragePlan, StoragePlanIntent

PLANNER_ROLES = (StorageRole.PLANNER.value,)


class FakeStorageStrategy:
    """Test double for IStorageStrategy — a stand-in for a future
    tier-specific planner, never a real one."""

    def __init__(self, tier: StorageTier, *, fail_with: Exception | None = None) -> None:
        self._tier = tier
        self._fail_with = fail_with

    @property
    def tier(self) -> StorageTier:
        return self._tier

    def plan(
        self,
        tenant_id: EntityIdType,
        event_fingerprint: str,
        category: str,
        retention_policy: RetentionPolicy,
        intent: StoragePlanIntent,
        now: datetime,
    ) -> StoragePlan:
        from siem_storage.application.dtos.storage_plan import StoragePlan

        if self._fail_with is not None:
            raise self._fail_with

        duration = retention_policy.duration_for(category, self._tier)
        is_archival_tier = self._tier in (StorageTier.COLD, StorageTier.ARCHIVE)
        return StoragePlan(
            tenant_id=tenant_id,
            event_fingerprint=event_fingerprint,
            category=category,
            tier=self._tier,
            intent=intent,
            retention_duration=duration,
            compression_intent=self._tier != StorageTier.HOT,
            encryption_requirement=True,
            archival_intent=is_archival_tier,
            planned_at=now,
        )


class RecordingWriter:
    def __init__(self) -> None:
        self.written: list[tuple[CanonicalEvent, StoragePlan]] = []

    def write(self, event: CanonicalEvent, plan: StoragePlan) -> None:
        self.written.append((event, plan))


@pytest.fixture
def writer() -> RecordingWriter:
    return RecordingWriter()


def make_canonical_event(
    *, tenant_id: EntityId | None = None, category: EventCategory = EventCategory.AUTHENTICATION
) -> CanonicalEvent:
    return build_canonical_event(
        tenant_id=tenant_id or EntityId.generate(),
        source=EventSource(source_type=EventSourceType.IDENTITY, vendor="okta"),
        category=category,
        outcome=EventOutcome.SUCCESS,
        occurred_at=datetime.now(UTC),
        schema_version=SchemaVersion(1, 0),
    )


def make_retention_policy(
    tenant_id: EntityId, category: str = "authentication", days: int = 30
) -> RetentionPolicy:
    return RetentionPolicy(
        tenant_id=str(tenant_id),
        durations_by_category={
            category: {
                StorageTier.HOT: RetentionDuration(days=days),
                StorageTier.WARM: RetentionDuration(days=days * 3),
                StorageTier.COLD: RetentionDuration(days=days * 12),
                StorageTier.ARCHIVE: RetentionDuration(days=days * 24),
            }
        },
    )
