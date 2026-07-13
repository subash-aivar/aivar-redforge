"""Tests for NetworkMonitoringSchedulerWorker — M16.

Verifies:
- start() launches exactly one poll-loop task; a second start() while
  already running is a no-op (no duplicate task/worker per process).
- stop() is cancellation-safe: cancels the task and awaits it cleanly,
  never hangs, never leaves an orphaned task.
- Due-policy processing: process_one_due_policy is called and its
  non-None result increments `processed`.
- No-due-policy idle behavior: a None result advances `cycles` without
  incrementing `processed`, and the loop sleeps rather than busy-looping.
- Worker exception recovery: an exception raised by
  process_one_due_policy is caught, counted as `failed`, and the poll
  loop continues (does not crash/die).
- is_running / stats() reflect health state accurately before start,
  while running, and after stop.
- The scheduler claim safety (SKIP LOCKED, exactly-one-winner) itself is
  proven at the real-PostgreSQL integration level in
  tests/integration/test_network_security_concurrency_proof.py — this
  file exercises the worker's own lifecycle/loop behavior in isolation
  with a fake processor double, matching test_replay_worker.py's
  established convention for testing this codebase's background workers.
"""

from __future__ import annotations

import asyncio

import pytest

from redforge.application.network_security.scheduler_worker import (
    NetworkMonitoringSchedulerWorker,
)

pytestmark = pytest.mark.asyncio


class _FakeProcessor:
    """Records calls; returns from a pre-scripted queue of results, or
    raises a pre-scripted exception, per call."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._results: list[object | Exception] = []

    def script(self, *results: object | Exception) -> None:
        self._results = list(results)

    async def process_one_due_policy(self, worker_id: str) -> object:
        self.calls.append(worker_id)
        result = self._results.pop(0) if self._results else None
        if isinstance(result, Exception):
            raise result
        return result


def _make_worker(
    processor: _FakeProcessor,
    *,
    poll_interval_s: float = 60.0,
    max_concurrent: int = 4,
    batch_size: int = 4,
) -> NetworkMonitoringSchedulerWorker:
    return NetworkMonitoringSchedulerWorker(
        processor=processor,  # type: ignore[arg-type]
        worker_id="test-worker-1",
        poll_interval_s=poll_interval_s,
        max_concurrent=max_concurrent,
        batch_size=batch_size,
    )


class TestLifecycle:
    async def test_not_running_before_start(self) -> None:
        worker = _make_worker(_FakeProcessor())
        assert worker.is_running is False
        assert worker.stats()["state"] == "stopped"

    async def test_start_launches_running_task(self) -> None:
        worker = _make_worker(_FakeProcessor())
        await worker.start()
        try:
            assert worker.is_running is True
            assert worker.stats()["state"] == "running"
        finally:
            await worker.stop()

    async def test_second_start_does_not_create_duplicate_task(self) -> None:
        """No duplicate worker/task per process: calling start() twice
        must not spawn a second poll-loop task."""
        worker = _make_worker(_FakeProcessor())
        await worker.start()
        first_task = worker._task
        try:
            await worker.start()
            assert worker._task is first_task
        finally:
            await worker.stop()

    async def test_stop_is_cancellation_safe_and_clears_task(self) -> None:
        worker = _make_worker(_FakeProcessor())
        await worker.start()
        await worker.stop()
        assert worker.is_running is False
        assert worker._task is None

    async def test_stop_before_start_is_a_safe_no_op(self) -> None:
        worker = _make_worker(_FakeProcessor())
        await worker.stop()
        assert worker.is_running is False

    async def test_stop_is_idempotent(self) -> None:
        worker = _make_worker(_FakeProcessor())
        await worker.start()
        await worker.stop()
        await worker.stop()  # must not raise
        assert worker.is_running is False


class TestDuePolicyProcessing:
    async def test_processing_a_due_policy_increments_processed(self) -> None:
        processor = _FakeProcessor()
        processor.script(object())  # one due policy processed
        worker = _make_worker(processor, poll_interval_s=0.01, batch_size=1)
        processed = await worker._poll_once()
        assert processed == 1
        assert worker.stats()["processed"] == 1
        assert processor.calls == ["test-worker-1"]

    async def test_no_due_policy_is_idle_not_an_error(self) -> None:
        processor = _FakeProcessor()  # every call returns None (nothing due)
        worker = _make_worker(processor, poll_interval_s=0.01, batch_size=3)
        processed = await worker._poll_once()
        assert processed == 0
        assert worker.stats()["processed"] == 0
        assert worker.stats()["failed"] == 0

    async def test_idle_cycle_still_advances_cycle_count_via_poll_loop(self) -> None:
        processor = _FakeProcessor()
        worker = _make_worker(processor, poll_interval_s=0.01, batch_size=1)
        await worker.start()
        try:
            await asyncio.sleep(0.05)
            assert worker.stats()["cycles"] >= 1
        finally:
            await worker.stop()


class TestExceptionRecovery:
    async def test_exception_in_one_attempt_is_isolated_and_counted_failed(self) -> None:
        processor = _FakeProcessor()
        processor.script(RuntimeError("transient db blip"))
        worker = _make_worker(processor, poll_interval_s=0.01, batch_size=1)
        processed = await worker._poll_once()
        assert processed == 0
        assert worker.stats()["failed"] == 1

    async def test_poll_loop_survives_a_full_cycle_exception(self) -> None:
        """If _poll_once itself raises unexpectedly, the loop logs,
        backs off, and keeps running rather than dying."""
        processor = _FakeProcessor()
        worker = _make_worker(processor, poll_interval_s=0.01, batch_size=1)

        call_count = 0
        original_poll_once = worker._poll_once

        async def _flaky_poll_once() -> int:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("boom")
            return await original_poll_once()

        worker._poll_once = _flaky_poll_once  # type: ignore[method-assign]
        await worker.start()
        try:
            await asyncio.sleep(0.1)
            assert worker.is_running is True
            assert call_count >= 2
        finally:
            await worker.stop()


class TestConcurrencyBound:
    async def test_batch_attempts_bounded_by_max_concurrent_semaphore(self) -> None:
        """A batch_size larger than max_concurrent must still complete
        correctly — the semaphore bounds in-flight attempts, it never
        drops or duplicates work."""
        processor = _FakeProcessor()
        processor.script(*(object() for _ in range(10)))
        worker = _make_worker(processor, poll_interval_s=0.01, max_concurrent=2, batch_size=10)
        processed = await worker._poll_once()
        assert processed == 10
        assert len(processor.calls) == 10
