"""Tests for backpressure controllers and pacers — Sprint 26."""

from __future__ import annotations

import asyncio

import pytest

from redforge.application.platform.backpressure import (
    BackpressureConfig,
    ProjectionPacer,
    ReplayPacer,
    SemaphoreBackpressureController,
    WatermarkBackpressureController,
)


class TestSemaphoreBackpressureController:
    async def test_acquire_and_release(self) -> None:
        ctrl = SemaphoreBackpressureController(max_concurrent=2)
        await ctrl.acquire()
        assert ctrl.queue_depth == 1
        ctrl.release()
        assert ctrl.queue_depth == 0

    async def test_is_throttled_at_max(self) -> None:
        ctrl = SemaphoreBackpressureController(max_concurrent=1)
        await ctrl.acquire()
        assert ctrl.is_throttled

    async def test_not_throttled_below_max(self) -> None:
        ctrl = SemaphoreBackpressureController(max_concurrent=3)
        await ctrl.acquire()
        assert not ctrl.is_throttled

    async def test_available_slots(self) -> None:
        ctrl = SemaphoreBackpressureController(max_concurrent=5)
        await ctrl.acquire()
        await ctrl.acquire()
        assert ctrl.available_slots == 3

    async def test_execute_runs_coroutine(self) -> None:
        ctrl = SemaphoreBackpressureController(max_concurrent=2)

        async def _work() -> str:
            return "hello"

        await ctrl.execute(_work)

    async def test_execute_releases_on_success(self) -> None:
        ctrl = SemaphoreBackpressureController(max_concurrent=2)

        async def work() -> str:
            return "done"

        await ctrl.execute(work)
        assert ctrl.queue_depth == 0

    async def test_execute_releases_on_failure(self) -> None:
        ctrl = SemaphoreBackpressureController(max_concurrent=2)

        async def boom() -> None:
            raise ValueError("oops")

        with pytest.raises(ValueError):
            await ctrl.execute(boom)
        assert ctrl.queue_depth == 0

    async def test_invalid_max_raises(self) -> None:
        with pytest.raises(ValueError):
            SemaphoreBackpressureController(max_concurrent=0)


class TestWatermarkBackpressureController:
    async def test_throttled_above_high_watermark(self) -> None:
        cfg = BackpressureConfig(
            max_concurrent=10, high_watermark=0.5, low_watermark=0.2,
            throttle_delay_s=0.0,
        )
        ctrl = WatermarkBackpressureController(cfg)
        for _ in range(5):
            await ctrl.acquire()
        assert ctrl.is_throttled

    async def test_not_throttled_below_high_watermark(self) -> None:
        cfg = BackpressureConfig(
            max_concurrent=10, high_watermark=0.8, low_watermark=0.4
        )
        ctrl = WatermarkBackpressureController(cfg)
        for _ in range(4):
            await ctrl.acquire()
        assert not ctrl.is_throttled

    async def test_resumes_below_low_watermark(self) -> None:
        cfg = BackpressureConfig(
            max_concurrent=10, high_watermark=0.5, low_watermark=0.3,
            throttle_delay_s=0.0,
        )
        ctrl = WatermarkBackpressureController(cfg)
        for _ in range(5):
            await ctrl.acquire()
        assert ctrl.is_throttled
        for _ in range(3):
            ctrl.release()
        assert not ctrl.is_throttled

    async def test_utilization(self) -> None:
        cfg = BackpressureConfig(max_concurrent=10, high_watermark=0.8, low_watermark=0.4)
        ctrl = WatermarkBackpressureController(cfg)
        for _ in range(4):
            await ctrl.acquire()
        assert ctrl.utilization == pytest.approx(0.4)

    def test_invalid_watermarks_raises(self) -> None:
        with pytest.raises(ValueError):
            BackpressureConfig(max_concurrent=10, high_watermark=0.3, low_watermark=0.8)


class TestProjectionPacer:
    async def test_no_sleep_within_batch(self) -> None:
        pacer = ProjectionPacer(batch_size=5, inter_batch_delay_s=0.0)
        for _ in range(4):
            await pacer.tick()
        assert pacer.events_since_last_pause == 4

    async def test_resets_at_batch_boundary(self) -> None:
        pacer = ProjectionPacer(batch_size=3, inter_batch_delay_s=0.0)
        for _ in range(3):
            await pacer.tick()
        assert pacer.events_since_last_pause == 0

    def test_reset(self) -> None:
        pacer = ProjectionPacer(batch_size=5)
        pacer._processed_since_pause = 3
        pacer.reset()
        assert pacer.events_since_last_pause == 0


class TestReplayPacer:
    async def test_pages_processed_increments(self) -> None:
        pacer = ReplayPacer(page_size=100, inter_page_delay_s=0.0)
        await pacer.page_processed(100)
        await pacer.page_processed(50)
        assert pacer.pages_processed == 2

    async def test_elapsed_increases(self) -> None:
        pacer = ReplayPacer()
        start = pacer.elapsed_s
        await asyncio.sleep(0.01)
        assert pacer.elapsed_s > start
