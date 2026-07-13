"""Tests for GracefulShutdownCoordinator — Sprint 26."""

from __future__ import annotations

import asyncio

from redforge.application.platform.lifecycle import GracefulShutdownCoordinator
from redforge.application.platform.runtime_contracts import LifecyclePhase


class TestGracefulShutdownCoordinator:
    async def test_initial_phase_is_initializing(self) -> None:
        coord = GracefulShutdownCoordinator()
        assert coord.phase == LifecyclePhase.INITIALIZING

    async def test_startup_runs_hooks_in_order(self) -> None:
        coord = GracefulShutdownCoordinator()
        order: list[str] = []
        coord.register_startup("first", lambda: _append(order, "first"))
        coord.register_startup("second", lambda: _append(order, "second"))
        await coord.startup()
        assert order == ["first", "second"]
        assert coord.phase == LifecyclePhase.RUNNING

    async def test_shutdown_runs_hooks_in_reverse(self) -> None:
        coord = GracefulShutdownCoordinator()
        order: list[str] = []
        coord.register_shutdown("first", lambda: _append(order, "first"))
        coord.register_shutdown("second", lambda: _append(order, "second"))
        await coord.startup()
        await coord.shutdown()
        assert order == ["second", "first"]
        assert coord.phase == LifecyclePhase.STOPPED

    async def test_shutdown_before_startup_is_safe(self) -> None:
        coord = GracefulShutdownCoordinator()
        await coord.shutdown()  # should not raise

    async def test_double_shutdown_is_safe(self) -> None:
        coord = GracefulShutdownCoordinator()
        await coord.startup()
        await coord.shutdown()
        await coord.shutdown()  # second call should be no-op

    async def test_hook_timeout_recorded_as_error(self) -> None:
        coord = GracefulShutdownCoordinator()

        async def slow() -> None:
            await asyncio.sleep(10)

        coord.register_startup("slow", slow, timeout_s=0.05)
        await coord.startup()
        errors = coord.errors
        assert len(errors) == 1
        assert "slow" in errors[0][0]

    async def test_hook_exception_recorded_not_raised(self) -> None:
        coord = GracefulShutdownCoordinator()

        async def boom() -> None:
            raise RuntimeError("startup failed")

        coord.register_startup("boom", boom)
        await coord.startup()  # should not raise
        assert len(coord.errors) == 1

    async def test_is_running_after_startup(self) -> None:
        coord = GracefulShutdownCoordinator()
        await coord.startup()
        assert coord.is_running

    async def test_not_running_after_shutdown(self) -> None:
        coord = GracefulShutdownCoordinator()
        await coord.startup()
        await coord.shutdown()
        assert not coord.is_running

    async def test_hook_names(self) -> None:
        coord = GracefulShutdownCoordinator()
        coord.register_startup("a", lambda: asyncio.sleep(0))
        coord.register_shutdown("b", lambda: asyncio.sleep(0))
        assert coord.startup_hook_names() == ["a"]
        assert coord.shutdown_hook_names() == ["b"]

    async def test_empty_coordinator_starts_and_stops(self) -> None:
        coord = GracefulShutdownCoordinator()
        await coord.startup()
        await coord.shutdown()
        assert coord.phase == LifecyclePhase.STOPPED


async def _append(lst: list[str], value: str) -> None:
    lst.append(value)
