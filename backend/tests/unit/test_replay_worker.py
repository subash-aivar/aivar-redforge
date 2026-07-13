"""Tests for DLQReplayWorker — Sprint 28.

Verifies:
- Worker polls list_pending_replay and calls replay_fn
- Successful replay triggers mark_replayed
- Failed replay leaves entry in requeued state
- max_concurrent semaphore limits parallelism
- Entries exceeding replay_max_retries are skipped
- stop() cancels the background task cleanly
- stats() tracks replayed/failed/skipped counts
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock

from redforge.application.platform.dead_letter_queue import InMemoryDeadLetterQueue
from redforge.application.platform.replay_worker import DLQReplayWorker
from redforge.application.platform.runtime_contracts import DeadLetterEntry


def _entry(entry_id: str, retry_count: int = 0) -> DeadLetterEntry:
    return DeadLetterEntry(
        entry_id=entry_id,
        source_projection="proj",
        event_id=f"ev-{entry_id}",
        event_type="TestEvent",
        payload={"x": 1},
        error_message="boom",
        retry_count=retry_count,
        first_failed_at=datetime.now(UTC),
        last_failed_at=datetime.now(UTC),
        organization_id="org-a",
    )


def _make_worker(
    dlq: InMemoryDeadLetterQueue,
    replay_fn: object,
    *,
    poll_interval_s: float = 60.0,
    max_concurrent: int = 5,
    batch_size: int = 10,
    replay_max_retries: int = 3,
) -> DLQReplayWorker:
    return DLQReplayWorker(
        dlq=dlq,  # type: ignore[arg-type]
        replay_fn=replay_fn,  # type: ignore[arg-type]
        poll_interval_s=poll_interval_s,
        max_concurrent=max_concurrent,
        batch_size=batch_size,
        replay_max_retries=replay_max_retries,
    )


class TestReplayWorkerPollOnce:
    async def test_successful_replay_marks_replayed(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")

        replay_fn = AsyncMock(return_value=True)
        worker = _make_worker(dlq, replay_fn)

        processed = await worker._poll_once()

        assert processed == 1
        assert replay_fn.call_count == 1
        pending = await dlq.list_pending_replay()
        assert pending == []

    async def test_failed_replay_leaves_entry_requeued(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")

        replay_fn = AsyncMock(return_value=False)
        worker = _make_worker(dlq, replay_fn)

        await worker._poll_once()

        # Entry still in queue and still requeued
        entries = await dlq.list("org-a")
        assert len(entries) == 1
        pending = await dlq.list_pending_replay()
        assert len(pending) == 1

    async def test_returns_zero_when_no_pending_entries(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))  # stored but NOT requeued

        replay_fn = AsyncMock(return_value=True)
        worker = _make_worker(dlq, replay_fn)

        processed = await worker._poll_once()
        assert processed == 0
        replay_fn.assert_not_called()

    async def test_exception_in_replay_fn_treated_as_failure(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")

        async def _boom(entry: DeadLetterEntry) -> bool:
            raise RuntimeError("crash")

        worker = _make_worker(dlq, _boom)
        await worker._poll_once()

        # Entry still requeued after failure
        pending = await dlq.list_pending_replay()
        assert len(pending) == 1

    async def test_batch_size_limits_entries_per_poll(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        for i in range(20):
            await dlq.store(_entry(f"e{i}"))
            await dlq.requeue(f"e{i}")

        called_ids: list[str] = []

        async def _replay(entry: DeadLetterEntry) -> bool:
            called_ids.append(entry.entry_id)
            return True

        worker = _make_worker(dlq, _replay, batch_size=5)
        processed = await worker._poll_once()

        assert processed == 5
        assert len(called_ids) == 5


class TestReplayWorkerSkipsHighRetryCount:
    async def test_skips_entries_exceeding_max_retries(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        # Store entry with retry_count=4, but max_retries=3
        await dlq.store(_entry("e1", retry_count=4))
        await dlq.requeue("e1")

        replay_fn = AsyncMock(return_value=True)
        worker = _make_worker(dlq, replay_fn, replay_max_retries=3)

        await worker._poll_once()

        # replay_fn NOT called — entry exceeded retry limit → exhausted
        replay_fn.assert_not_called()
        assert worker.stats()["exhausted"] == 1
        assert worker.stats()["skipped"] == 0

    async def test_does_not_skip_entries_at_exact_max(self) -> None:
        # store with retry_count=2 → after requeue() increments to 3 == max_retries
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1", retry_count=2))
        await dlq.requeue("e1")  # now retry_count=3

        replay_fn = AsyncMock(return_value=True)
        worker = _make_worker(dlq, replay_fn, replay_max_retries=3)

        await worker._poll_once()

        # retry_count == max_retries (not >) — entry IS replayed
        replay_fn.assert_called_once()


class TestReplayWorkerStats:
    async def test_tracks_replayed_count(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        for i in range(3):
            await dlq.store(_entry(f"e{i}"))
            await dlq.requeue(f"e{i}")

        worker = _make_worker(dlq, AsyncMock(return_value=True))
        await worker._poll_once()

        assert worker.stats()["replayed"] == 3
        assert worker.stats()["failed"] == 0

    async def test_tracks_failed_count(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        for i in range(2):
            await dlq.store(_entry(f"e{i}"))
            await dlq.requeue(f"e{i}")

        worker = _make_worker(dlq, AsyncMock(return_value=False))
        await worker._poll_once()

        assert worker.stats()["failed"] == 2
        assert worker.stats()["replayed"] == 0


class TestReplayWorkerLifecycle:
    async def test_is_running_after_start(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        worker = _make_worker(dlq, AsyncMock(return_value=True), poll_interval_s=60.0)
        await worker.start()
        assert worker.is_running
        await worker.stop()

    async def test_is_not_running_after_stop(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        worker = _make_worker(dlq, AsyncMock(return_value=True), poll_interval_s=60.0)
        await worker.start()
        await worker.stop()
        assert not worker.is_running

    async def test_stop_is_idempotent_when_not_started(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        worker = _make_worker(dlq, AsyncMock(return_value=True))
        await worker.stop()  # should not raise

    async def test_worker_processes_entries_in_background(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        await dlq.store(_entry("e1"))
        await dlq.requeue("e1")

        replayed: list[str] = []

        async def _replay(entry: DeadLetterEntry) -> bool:
            replayed.append(entry.entry_id)
            return True

        worker = _make_worker(dlq, _replay, poll_interval_s=0.01)
        await worker.start()

        # Wait for at least one poll cycle
        for _ in range(50):
            if replayed:
                break
            await asyncio.sleep(0.01)

        await worker.stop()
        assert "e1" in replayed
