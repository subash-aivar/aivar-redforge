"""Tests for InMemoryDeadLetterQueue and PoisonEventDetector — Sprint 26."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.application.platform.dead_letter_queue import (
    DeadLetterEntryNotFoundError,
    DeadLetterQueueFullError,
    InMemoryDeadLetterQueue,
    PoisonEventDetector,
)
from redforge.application.platform.runtime_contracts import DeadLetterEntry


def _entry(
    entry_id: str = "e1",
    event_id: str = "ev1",
    org_id: str = "org1",
    projection: str = "campaign_summary",
    retry_count: int = 0,
) -> DeadLetterEntry:
    now = datetime.now(UTC)
    return DeadLetterEntry(
        entry_id=entry_id,
        source_projection=projection,
        event_id=event_id,
        event_type="test.Event",
        payload={"key": "value"},
        error_message="boom",
        retry_count=retry_count,
        first_failed_at=now,
        last_failed_at=now,
        organization_id=org_id,
    )


class TestInMemoryDLQ:
    async def test_store_and_list(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        results = await dlq.list("org1")
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    async def test_list_filters_by_org(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1", org_id="org1"))
        await dlq.store(_entry("e2", org_id="org2"))
        results = await dlq.list("org1")
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    async def test_list_filters_by_projection(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1", projection="campaign_summary"))
        await dlq.store(_entry("e2", projection="risk_projection"))
        results = await dlq.list("org1", source_projection="campaign_summary")
        assert len(results) == 1

    async def test_list_max_count(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        for i in range(5):
            await dlq.store(_entry(f"e{i}"))
        results = await dlq.list("org1", max_count=2)
        assert len(results) == 2

    async def test_store_idempotent(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.store(_entry("e1"))
        assert await dlq.depth("org1") == 1

    async def test_requeue_increments_retry_count(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1", retry_count=0))
        updated = await dlq.requeue("e1")
        assert updated.retry_count == 1

    async def test_requeue_missing_raises(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        with pytest.raises(DeadLetterEntryNotFoundError):
            await dlq.requeue("nonexistent")

    async def test_discard_removes_entry(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.discard("e1")
        assert await dlq.depth("org1") == 0

    async def test_discard_missing_raises(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        with pytest.raises(DeadLetterEntryNotFoundError):
            await dlq.discard("nonexistent")

    async def test_depth_per_org(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1", org_id="org1"))
        await dlq.store(_entry("e2", org_id="org1"))
        await dlq.store(_entry("e3", org_id="org2"))
        assert await dlq.depth("org1") == 2
        assert await dlq.depth("org2") == 1

    async def test_full_raises(self) -> None:
        dlq = InMemoryDeadLetterQueue(max_size=2)
        await dlq.store(_entry("e1"))
        await dlq.store(_entry("e2"))
        with pytest.raises(DeadLetterQueueFullError):
            await dlq.store(_entry("e3"))

    async def test_clear_all(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        count = dlq.clear_all()
        assert count == 1
        assert await dlq.total_depth() == 0


class TestPoisonEventDetector:
    def test_not_poison_initially(self) -> None:
        det = PoisonEventDetector(poison_threshold=3)
        assert not det.is_poison("proj", "ev1")

    def test_becomes_poison_at_threshold(self) -> None:
        det = PoisonEventDetector(poison_threshold=3)
        det.record_failure("proj", "ev1")
        det.record_failure("proj", "ev1")
        assert not det.is_poison("proj", "ev1")
        det.record_failure("proj", "ev1")
        assert det.is_poison("proj", "ev1")

    def test_failure_count_increments(self) -> None:
        det = PoisonEventDetector(poison_threshold=3)
        count = det.record_failure("proj", "ev1")
        assert count == 1
        count = det.record_failure("proj", "ev1")
        assert count == 2

    def test_reset_clears_count(self) -> None:
        det = PoisonEventDetector(poison_threshold=3)
        det.record_failure("proj", "ev1")
        det.record_failure("proj", "ev1")
        det.record_failure("proj", "ev1")
        assert det.is_poison("proj", "ev1")
        det.reset("proj", "ev1")
        assert not det.is_poison("proj", "ev1")

    def test_all_poison_events(self) -> None:
        det = PoisonEventDetector(poison_threshold=2)
        det.record_failure("proj", "ev1")
        det.record_failure("proj", "ev1")
        det.record_failure("proj", "ev2")
        poisons = det.all_poison_events()
        assert ("proj", "ev1") in poisons
        assert ("proj", "ev2") not in poisons

    def test_isolated_per_event(self) -> None:
        det = PoisonEventDetector(poison_threshold=2)
        det.record_failure("proj", "ev1")
        det.record_failure("proj", "ev2")
        assert not det.is_poison("proj", "ev1")
        assert not det.is_poison("proj", "ev2")
