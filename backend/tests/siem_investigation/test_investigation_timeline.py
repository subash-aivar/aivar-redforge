from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.shared.identifiers import EntityId
from siem_investigation.domain.aggregates.investigation_timeline import InvestigationTimeline
from siem_investigation.domain.exceptions.domain_exceptions import (
    DuplicateTimelineEntryError,
    EmptyScopeRefError,
    TenantMismatch,
)
from siem_investigation.domain.value_objects.enums import TimelineScopeType
from siem_investigation.domain.value_objects.identifiers import InvestigationTimelineId
from siem_investigation.domain.value_objects.timeline_entry import TimelineEntry

BASE = datetime.now(UTC)


def _tenant() -> EntityId:
    return EntityId.generate()


def _create(tenant_id: EntityId | None = None) -> InvestigationTimeline:
    return InvestigationTimeline.create(
        timeline_id=InvestigationTimelineId.generate(),
        tenant_id=tenant_id or _tenant(),
        scope_type=TimelineScopeType.ENTITY,
        scope_ref="asset-42",
    )


def _entry(event_id: str, offset_minutes: int) -> TimelineEntry:
    return TimelineEntry(
        event_id=event_id,
        occurred_at=BASE + timedelta(minutes=offset_minutes),
        category="authentication",
        summary=f"event {event_id}",
    )


def test_create_rejects_blank_scope_ref() -> None:
    with pytest.raises(EmptyScopeRefError):
        InvestigationTimeline.create(
            timeline_id=InvestigationTimelineId.generate(),
            tenant_id=_tenant(),
            scope_type=TimelineScopeType.ALERT,
            scope_ref="  ",
        )


def test_add_entry_out_of_order_is_stored_chronologically() -> None:
    """Cross-source events can arrive in any order — the timeline must
    always read back in occurred_at order (M42 Phase 9 acceptance
    criteria: "correctly ordered, cross-source events")."""
    tenant_id = _tenant()
    timeline = _create(tenant_id)

    timeline.add_entry(tenant_id, _entry("evt-3", 30))
    timeline.add_entry(tenant_id, _entry("evt-1", 10))
    timeline.add_entry(tenant_id, _entry("evt-2", 20))

    assert [e.event_id for e in timeline.entries] == ["evt-1", "evt-2", "evt-3"]


def test_add_entry_duplicate_event_id_raises() -> None:
    tenant_id = _tenant()
    timeline = _create(tenant_id)
    timeline.add_entry(tenant_id, _entry("evt-1", 10))
    with pytest.raises(DuplicateTimelineEntryError):
        timeline.add_entry(tenant_id, _entry("evt-1", 20))


def test_add_entry_wrong_tenant_raises_tenant_mismatch() -> None:
    timeline = _create()
    with pytest.raises(TenantMismatch):
        timeline.add_entry(_tenant(), _entry("evt-1", 10))


def test_timeline_entry_rejects_blank_event_id() -> None:
    with pytest.raises(ValueError, match="event_id"):
        TimelineEntry(event_id="", occurred_at=BASE, category="network", summary="x")


def test_timeline_entry_rejects_blank_summary() -> None:
    with pytest.raises(ValueError, match="summary"):
        TimelineEntry(event_id="evt-1", occurred_at=BASE, category="network", summary="  ")
