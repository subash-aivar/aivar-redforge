"""Tests for DefaultWorkerSupervisor and DefaultProjectionSupervisor — Sprint 26."""

from __future__ import annotations

import asyncio

import pytest

from redforge.application.platform.runtime_contracts import WorkerState
from redforge.application.platform.supervisor import (
    DefaultProjectionSupervisor,
    DefaultWorkerSupervisor,
)


class TestDefaultWorkerSupervisor:
    async def test_start_runs_worker(self) -> None:
        ran = []

        async def work() -> None:
            ran.append(True)

        sup = DefaultWorkerSupervisor()
        sup.register_worker("w1", work)
        await sup.start_worker("w1")
        await asyncio.sleep(0.05)
        assert ran

    async def test_list_workers(self) -> None:
        sup = DefaultWorkerSupervisor()
        sup.register_worker("w1", lambda: asyncio.sleep(0))
        assert "w1" in sup.list_workers()

    async def test_worker_health_running(self) -> None:
        barrier = asyncio.Event()

        async def work() -> None:
            await barrier.wait()

        sup = DefaultWorkerSupervisor()
        sup.register_worker("w1", work)
        await sup.start_worker("w1")
        await asyncio.sleep(0.01)
        health = await sup.worker_health("w1")
        assert health.worker_id == "w1"
        assert health.state in (WorkerState.RUNNING, WorkerState.STARTING)
        barrier.set()

    async def test_stop_worker(self) -> None:
        barrier = asyncio.Event()

        async def work() -> None:
            await barrier.wait()

        sup = DefaultWorkerSupervisor()
        sup.register_worker("w1", work)
        await sup.start_worker("w1")
        await asyncio.sleep(0.01)
        await sup.stop_worker("w1")
        health = await sup.worker_health("w1")
        assert health.state == WorkerState.STOPPED

    async def test_unknown_worker_raises(self) -> None:
        sup = DefaultWorkerSupervisor()
        with pytest.raises(KeyError):
            await sup.start_worker("unknown")

    async def test_restart_resets_count(self) -> None:
        count = {"c": 0}

        async def work() -> None:
            count["c"] += 1
            await asyncio.sleep(100)

        sup = DefaultWorkerSupervisor()
        sup.register_worker("w1", work)
        await sup.start_worker("w1")
        await asyncio.sleep(0.01)
        await sup.restart_worker("w1")
        health = await sup.worker_health("w1")
        assert health.restart_count == 0

    async def test_exhausted_callback(self) -> None:
        exhausted: list[str] = []

        async def on_exhausted(worker_id: str) -> None:
            exhausted.append(worker_id)

        async def always_fail() -> None:
            raise RuntimeError("always fail")

        sup = DefaultWorkerSupervisor(
            max_restarts=2,
            base_delay_s=0.01,
            max_delay_s=0.05,
            on_exhausted=on_exhausted,
        )
        sup.register_worker("w1", always_fail)
        await sup.start_worker("w1")
        await asyncio.sleep(0.5)
        health = await sup.worker_health("w1")
        assert health.state == WorkerState.FAILED
        assert "w1" in exhausted

    async def test_start_idempotent_when_running(self) -> None:
        barrier = asyncio.Event()

        async def work() -> None:
            await barrier.wait()

        sup = DefaultWorkerSupervisor()
        sup.register_worker("w1", work)
        await sup.start_worker("w1")
        await sup.start_worker("w1")  # should be no-op
        barrier.set()

    async def test_worker_health_unregistered(self) -> None:
        sup = DefaultWorkerSupervisor()
        health = await sup.worker_health("ghost")
        assert health.state == WorkerState.STOPPED
        assert "not registered" in (health.error_message or "")


class TestDefaultProjectionSupervisor:
    async def test_register_and_list(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("campaign_summary")
        assert "campaign_summary" in sup.list_projections()

    async def test_start_sets_running(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("campaign_summary")
        await sup.start("campaign_summary")
        health = await sup.health("campaign_summary")
        assert health.state == WorkerState.RUNNING

    async def test_stop_sets_stopped(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("campaign_summary")
        await sup.start("campaign_summary")
        await sup.stop("campaign_summary")
        health = await sup.health("campaign_summary")
        assert health.state == WorkerState.STOPPED

    async def test_record_success_advances_position(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("campaign_summary")
        sup.record_success("campaign_summary", 42)
        health = await sup.health("campaign_summary")
        assert health.last_event_position == 42

    async def test_record_failure_sets_error(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("campaign_summary")
        sup.record_failure("campaign_summary", "boom")
        health = await sup.health("campaign_summary")
        assert health.error_message == "boom"

    async def test_restart_increments_count(self) -> None:
        sup = DefaultProjectionSupervisor(max_restarts=5)
        sup.register("campaign_summary")
        await sup.restart("campaign_summary")
        health = await sup.health("campaign_summary")
        assert health.restart_count == 1

    async def test_restart_exhausted_marks_failed(self) -> None:
        sup = DefaultProjectionSupervisor(max_restarts=2)
        sup.register("p")
        await sup.restart("p")
        await sup.restart("p")
        await sup.restart("p")
        health = await sup.health("p")
        assert health.state == WorkerState.FAILED

    async def test_poison_event_detection(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("p")
        sup.record_event_failure("p", "ev1")
        sup.record_event_failure("p", "ev1")
        assert not sup.is_poison_event("p", "ev1", poison_threshold=3)
        sup.record_event_failure("p", "ev1")
        assert sup.is_poison_event("p", "ev1", poison_threshold=3)

    async def test_reset_event_failures(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("p")
        for _ in range(3):
            sup.record_event_failure("p", "ev1")
        sup.reset_event_failures("p", "ev1")
        assert not sup.is_poison_event("p", "ev1", poison_threshold=3)

    async def test_poison_skip_increments_count(self) -> None:
        sup = DefaultProjectionSupervisor()
        sup.register("p")
        sup.record_poison_skip("p")
        sup.record_poison_skip("p")
        health = await sup.health("p")
        assert health.poison_event_count == 2

    async def test_maybe_restart_returns_true_when_allowed(self) -> None:
        sup = DefaultProjectionSupervisor(max_restarts=5)
        sup.register("p")
        restarted = await sup.maybe_restart("p")
        assert restarted

    async def test_maybe_restart_returns_false_when_exhausted(self) -> None:
        sup = DefaultProjectionSupervisor(max_restarts=1)
        sup.register("p")
        await sup.restart("p")
        restarted = await sup.maybe_restart("p")
        assert not restarted

    async def test_health_unregistered(self) -> None:
        sup = DefaultProjectionSupervisor()
        health = await sup.health("ghost")
        assert "not registered" in (health.error_message or "")
