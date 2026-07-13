"""Tests for HeartbeatMonitor and PeriodicHeartbeatEmitter — Sprint 26."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from redforge.application.platform.heartbeat import (
    HeartbeatMonitor,
    PeriodicHeartbeatEmitter,
    make_heartbeat_health_checker,
)
from redforge.application.platform.runtime_contracts import HealthStatus, Heartbeat


def _beat(component_id: str = "projection_engine", sequence: int = 1) -> Heartbeat:
    return Heartbeat(
        component_id=component_id,
        beat_at=datetime.now(UTC),
        sequence=sequence,
        metadata={},
    )


class TestHeartbeatMonitor:
    def test_is_alive_after_recent_beat(self) -> None:
        monitor = HeartbeatMonitor()
        monitor.record(_beat("comp"))
        assert monitor.is_alive("comp", max_age_s=10.0)

    def test_not_alive_before_any_beat(self) -> None:
        monitor = HeartbeatMonitor()
        assert not monitor.is_alive("comp", max_age_s=10.0)

    def test_last_beat(self) -> None:
        monitor = HeartbeatMonitor()
        beat = _beat("comp", sequence=5)
        monitor.record(beat)
        assert monitor.last_beat("comp") is beat

    def test_last_beat_missing(self) -> None:
        monitor = HeartbeatMonitor()
        assert monitor.last_beat("unknown") is None

    def test_age_increases_over_time(self) -> None:
        import time
        monitor = HeartbeatMonitor()
        monitor.record(_beat("comp"))
        time.sleep(0.01)
        age = monitor.age_s("comp")
        assert age is not None
        assert age >= 0.01

    def test_age_none_for_unregistered(self) -> None:
        monitor = HeartbeatMonitor()
        assert monitor.age_s("unknown") is None

    def test_missed_beats(self) -> None:
        import time
        monitor = HeartbeatMonitor()
        monitor.record(_beat("old"))
        time.sleep(0.05)
        monitor.record(_beat("new"))
        missed = monitor.missed_beats(max_age_s=0.03)
        assert "old" in missed
        assert "new" not in missed

    def test_registered_components(self) -> None:
        monitor = HeartbeatMonitor()
        monitor.record(_beat("a"))
        monitor.record(_beat("b"))
        assert set(monitor.registered_components()) == {"a", "b"}

    def test_clear(self) -> None:
        monitor = HeartbeatMonitor()
        monitor.record(_beat("comp"))
        monitor.clear("comp")
        assert not monitor.is_alive("comp", max_age_s=10.0)

    def test_most_recent_beat_is_alive(self) -> None:
        monitor = HeartbeatMonitor()
        for i in range(3):
            monitor.record(_beat("comp", sequence=i))
        assert monitor.is_alive("comp", max_age_s=5.0)
        assert monitor.last_beat("comp") is not None
        assert monitor.last_beat("comp").sequence == 2  # type: ignore[union-attr]


class TestPeriodicHeartbeatEmitter:
    async def test_beat_records_to_monitor(self) -> None:
        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter("comp", monitor, interval_s=100.0)
        beat = await emitter.beat()
        assert beat.component_id == "comp"
        assert beat.sequence == 1
        assert monitor.is_alive("comp", max_age_s=5.0)

    async def test_sequence_increments(self) -> None:
        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter("comp", monitor, interval_s=100.0)
        b1 = await emitter.beat()
        b2 = await emitter.beat()
        assert b2.sequence == b1.sequence + 1

    async def test_start_and_stop(self) -> None:
        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter("comp", monitor, interval_s=0.05)
        await emitter.start()
        await asyncio.sleep(0.12)
        await emitter.stop()
        # Should have emitted at least 2 beats
        assert emitter._sequence >= 2

    async def test_start_idempotent(self) -> None:
        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter("comp", monitor, interval_s=100.0)
        await emitter.start()
        await emitter.start()  # second call should not create a new task
        await emitter.stop()

    async def test_is_alive(self) -> None:
        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter("comp", monitor, interval_s=100.0)
        await emitter.beat()
        assert emitter.is_alive

    async def test_component_id(self) -> None:
        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter("my_component", monitor, interval_s=100.0)
        assert emitter.component_id == "my_component"

    async def test_metadata_factory(self) -> None:
        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter(
            "comp", monitor, interval_s=100.0,
            metadata_factory=lambda: {"workers": 3},
        )
        beat = await emitter.beat()
        assert beat.metadata == {"workers": 3}


class TestHeartbeatHealthChecker:
    async def test_healthy_when_alive(self) -> None:
        monitor = HeartbeatMonitor()
        monitor.record(_beat("comp"))
        checker = make_heartbeat_health_checker("comp", "worker", monitor, max_age_s=10.0)
        result = await checker()
        assert result.status == HealthStatus.HEALTHY

    async def test_unhealthy_when_no_beat(self) -> None:
        monitor = HeartbeatMonitor()
        checker = make_heartbeat_health_checker("comp", "worker", monitor, max_age_s=10.0)
        result = await checker()
        assert result.status == HealthStatus.UNHEALTHY

    async def test_unhealthy_when_beat_too_old(self) -> None:
        import time
        monitor = HeartbeatMonitor()
        monitor.record(_beat("comp"))
        time.sleep(0.05)
        checker = make_heartbeat_health_checker("comp", "worker", monitor, max_age_s=0.01)
        result = await checker()
        assert result.status == HealthStatus.UNHEALTHY
