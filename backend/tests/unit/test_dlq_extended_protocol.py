"""Tests for InMemoryDeadLetterQueue Sprint 28 extensions.

Verifies:
- list_pending_replay() returns only requeued entries
- mark_replayed() removes the entry
- total_depth() returns cross-org count (async)
- requeue() adds to pending replay set
- discard() removes from pending replay set
- clear_all() also clears requeued set
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.application.platform.dead_letter_queue import InMemoryDeadLetterQueue
from redforge.application.platform.runtime_contracts import DeadLetterEntry


def _entry(entry_id: str, org: str = "org-a") -> DeadLetterEntry:
    return DeadLetterEntry(
        entry_id=entry_id,
        source_projection="proj",
        event_id=f"ev-{entry_id}",
        event_type="TestEvent",
        payload={"x": 1},
        error_message="boom",
        retry_count=0,
        first_failed_at=datetime.now(UTC),
        last_failed_at=datetime.now(UTC),
        organization_id=org,
    )


class TestListPendingReplay:
    async def test_empty_when_no_requeued_entries(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        result = await dlq.list_pending_replay()
        assert result == []

    async def test_returns_requeued_entries(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.store(_entry("e2"))
        await dlq.requeue("e1")
        result = await dlq.list_pending_replay()
        assert len(result) == 1
        assert result[0].entry_id == "e1"

    async def test_max_count_limits_result(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        for i in range(10):
            e = _entry(f"e{i}")
            await dlq.store(e)
            await dlq.requeue(f"e{i}")
        result = await dlq.list_pending_replay(max_count=3)
        assert len(result) == 3

    async def test_respects_insertion_order(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        for i in range(5):
            e = _entry(f"e{i}")
            await dlq.store(e)
            await dlq.requeue(f"e{i}")
        result = await dlq.list_pending_replay()
        ids = [r.entry_id for r in result]
        assert ids == ["e0", "e1", "e2", "e3", "e4"]


class TestMarkReplayed:
    async def test_removes_entry_from_queue(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")
        await dlq.mark_replayed("e1")
        entries = await dlq.list("org-a")
        assert entries == []

    async def test_removes_from_pending_replay(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")
        await dlq.mark_replayed("e1")
        pending = await dlq.list_pending_replay()
        assert pending == []

    async def test_idempotent_on_missing_entry(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        # Should not raise if entry doesn't exist
        await dlq.mark_replayed("nonexistent")


class TestTotalDepth:
    async def test_returns_zero_when_empty(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        assert await dlq.total_depth() == 0

    async def test_counts_across_all_orgs(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1", "org-a"))
        await dlq.store(_entry("e2", "org-b"))
        await dlq.store(_entry("e3", "org-c"))
        assert await dlq.total_depth() == 3

    async def test_decrements_on_mark_replayed(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")
        assert await dlq.total_depth() == 1
        await dlq.mark_replayed("e1")
        assert await dlq.total_depth() == 0


class TestDiscardClearsRequeued:
    async def test_discard_removes_from_pending_replay(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")
        await dlq.discard("e1")
        pending = await dlq.list_pending_replay()
        assert pending == []


class TestClearAll:
    async def test_clears_requeued_set(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")
        dlq.clear_all()
        pending = await dlq.list_pending_replay()
        assert pending == []
        assert await dlq.total_depth() == 0
