from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from analytics.infrastructure.projections.event_projection_store import (
    EventProjectionStore,
)


def test_idempotent_ingest() -> None:
    store = EventProjectionStore()
    tid = uuid4()
    now = datetime.now(UTC)
    assert store.ingest(
        tid,
        domain="vulnerability",
        event_id="e1",
        event_type="VulnerabilityInstanceDiscovered",
        event_ts=now,
        payload={"asset_ref_id": "a"},
    )
    assert not store.ingest(
        tid,
        domain="vulnerability",
        event_id="e1",
        event_type="VulnerabilityInstanceDiscovered",
        event_ts=now,
        payload={"asset_ref_id": "a"},
    )
    assert len(store.list_events(tid, "vulnerability")) == 1


def test_tenant_isolation() -> None:
    store = EventProjectionStore()
    a, b = uuid4(), uuid4()
    now = datetime.now(UTC)
    store.ingest(
        a,
        domain="detection",
        event_id="e1",
        event_type="DetectionFindingProduced",
        event_ts=now,
        payload={},
    )
    assert store.list_events(b, "detection") == []
    assert len(store.list_events(a, "detection")) == 1


def test_retention_marks_archived_not_deleted() -> None:
    store = EventProjectionStore()
    tid = uuid4()
    old = datetime.now(UTC) - timedelta(days=800)
    store.ingest(
        tid,
        domain="campaign",
        event_id="old",
        event_type="CampaignCompleted",
        event_ts=old,
        payload={},
    )
    n = store.mark_archived_before(tid, "campaign", datetime.now(UTC) - timedelta(days=730))
    assert n == 1
    assert store.list_events(tid, "campaign") == []
    assert len(store.list_events(tid, "campaign", include_archived=True)) == 1
