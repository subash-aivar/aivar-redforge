"""Tests for SemaphoreBulkhead and BulkheadRegistry — Sprint 26."""

from __future__ import annotations

import asyncio

import pytest

from redforge.application.platform.bulkhead import (
    BulkheadConfig,
    BulkheadFullError,
    BulkheadRegistry,
    SemaphoreBulkhead,
)


class TestSemaphoreBulkhead:
    async def test_execute_success(self) -> None:
        bh = SemaphoreBulkhead(BulkheadConfig(max_concurrent=2))

        async def work() -> str:
            return "result"

        result = await bh.execute(work)
        assert result == "result"

    async def test_active_calls_tracks_concurrent(self) -> None:
        bh = SemaphoreBulkhead(BulkheadConfig(max_concurrent=5))
        barrier = asyncio.Event()
        active_during: list[int] = []

        async def work() -> None:
            active_during.append(bh.active_calls)
            await barrier.wait()

        tasks = [asyncio.create_task(bh.execute(work)) for _ in range(3)]
        await asyncio.sleep(0.01)
        assert bh.active_calls == 3
        barrier.set()
        await asyncio.gather(*tasks)
        assert bh.active_calls == 0

    async def test_rejects_when_full_after_timeout(self) -> None:
        bh = SemaphoreBulkhead(BulkheadConfig(
            max_concurrent=1, max_wait_duration_s=0.05, bulkhead_id="test"
        ))
        barrier = asyncio.Event()

        async def hold() -> None:
            await barrier.wait()

        task = asyncio.create_task(bh.execute(hold))
        await asyncio.sleep(0.01)

        with pytest.raises(BulkheadFullError) as exc_info:
            await bh.execute(hold)

        assert exc_info.value.bulkhead_id == "test"
        barrier.set()
        await task

    async def test_releases_on_exception(self) -> None:
        bh = SemaphoreBulkhead(BulkheadConfig(max_concurrent=2))

        async def boom() -> None:
            raise RuntimeError("oops")

        with pytest.raises(RuntimeError):
            await bh.execute(boom)
        assert bh.active_calls == 0
        assert bh.available_slots == 2

    async def test_stats(self) -> None:
        bh = SemaphoreBulkhead(BulkheadConfig(
            max_concurrent=5, bulkhead_id="stats_test"
        ))

        async def work() -> str:
            return "ok"

        await bh.execute(work)
        stats = bh.stats()
        assert stats.bulkhead_id == "stats_test"
        assert stats.total_calls == 1
        assert stats.rejected_calls == 0
        assert stats.max_concurrent == 5

    async def test_rejected_calls_tracked(self) -> None:
        bh = SemaphoreBulkhead(BulkheadConfig(
            max_concurrent=1, max_wait_duration_s=0.01
        ))
        barrier = asyncio.Event()

        async def hold() -> None:
            await barrier.wait()

        task = asyncio.create_task(bh.execute(hold))
        await asyncio.sleep(0.01)
        with pytest.raises(BulkheadFullError):
            await bh.execute(hold)

        assert bh.stats().rejected_calls == 1
        barrier.set()
        await task

    def test_config_validation(self) -> None:
        with pytest.raises(ValueError):
            BulkheadConfig(max_concurrent=0)
        with pytest.raises(ValueError):
            BulkheadConfig(max_wait_duration_s=-1)

    async def test_multiple_concurrent_succeed(self) -> None:
        bh = SemaphoreBulkhead(BulkheadConfig(max_concurrent=5))
        results = await asyncio.gather(*[
            bh.execute(lambda: asyncio.sleep(0))
            for _ in range(5)
        ])
        assert len(results) == 5
        assert bh.active_calls == 0


class TestBulkheadRegistry:
    def test_register_and_get(self) -> None:
        reg = BulkheadRegistry()
        bh = SemaphoreBulkhead()
        reg.register("kg", bh)
        assert reg.get("kg") is bh

    def test_get_missing_returns_none(self) -> None:
        reg = BulkheadRegistry()
        assert reg.get("nonexistent") is None

    def test_get_or_create(self) -> None:
        reg = BulkheadRegistry()
        bh1 = reg.get_or_create("kg", max_concurrent=5)
        bh2 = reg.get_or_create("kg")
        assert bh1 is bh2

    def test_all_stats(self) -> None:
        reg = BulkheadRegistry()
        reg.register("a", SemaphoreBulkhead(BulkheadConfig(bulkhead_id="a")))
        reg.register("b", SemaphoreBulkhead(BulkheadConfig(bulkhead_id="b")))
        stats = reg.all_stats()
        assert set(stats.keys()) == {"a", "b"}

    def test_list_names(self) -> None:
        reg = BulkheadRegistry()
        reg.register("x", SemaphoreBulkhead())
        assert "x" in reg.list_names()
