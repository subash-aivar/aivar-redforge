"""Heartbeat framework — Sprint 26.

Provides liveness signalling for long-running components:
- HeartbeatMonitor: receives and tracks heartbeats, detects missed beats.
- PeriodicHeartbeatEmitter: emits a heartbeat every interval_s via asyncio task.
- HeartbeatHealthChecker: bridges HeartbeatMonitor to the RuntimeHealthEngine.

Missed beat detection:
    A component is considered alive if its last beat was received within
    `max_age_s` seconds. This is checked synchronously — no async needed.

Design rules:
- No infrastructure imports.
- HeartbeatMonitor is thread-safe (sync reads from health engine thread).
- PeriodicHeartbeatEmitter manages its own asyncio task lifecycle.
- Sequence numbers are monotonically increasing per component.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.application.platform.runtime_contracts import (
    ComponentHealth,
    HealthStatus,
    Heartbeat,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


def _utc_now() -> datetime:
    return datetime.now(UTC)


class HeartbeatMonitor:
    """Thread-safe store of the most recent heartbeat per component.

    Components register by emitting their first heartbeat. The monitor
    tracks the last received beat and the monotonic timestamp for
    age calculation without clock-skew issues.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._beats: dict[str, tuple[Heartbeat, float]] = {}  # (beat, mono_ts)

    def record(self, beat: Heartbeat) -> None:
        """Record a received heartbeat."""
        with self._lock:
            self._beats[beat.component_id] = (beat, time.monotonic())

    def is_alive(self, component_id: str, max_age_s: float) -> bool:
        """Return True if a heartbeat was received within max_age_s seconds."""
        with self._lock:
            entry = self._beats.get(component_id)
        if entry is None:
            return False
        _, mono_ts = entry
        return (time.monotonic() - mono_ts) <= max_age_s

    def last_beat(self, component_id: str) -> Heartbeat | None:
        with self._lock:
            entry = self._beats.get(component_id)
            return entry[0] if entry is not None else None

    def age_s(self, component_id: str) -> float | None:
        """Seconds since last heartbeat. None if never received."""
        with self._lock:
            entry = self._beats.get(component_id)
        if entry is None:
            return None
        _, mono_ts = entry
        return time.monotonic() - mono_ts

    def missed_beats(self, max_age_s: float) -> list[str]:
        """Return component IDs whose last beat exceeded max_age_s."""
        now = time.monotonic()
        with self._lock:
            return [
                cid for cid, (_, ts) in self._beats.items()
                if (now - ts) > max_age_s
            ]

    def registered_components(self) -> list[str]:
        with self._lock:
            return list(self._beats.keys())

    def clear(self, component_id: str) -> None:
        with self._lock:
            self._beats.pop(component_id, None)


class PeriodicHeartbeatEmitter:
    """Emits a heartbeat for a component on a fixed interval.

    Manages its own asyncio.Task — call start() to begin emitting,
    stop() to cancel. The task is non-daemonic by default so that
    the GracefulShutdownCoordinator can stop it explicitly.

    Usage::

        monitor = HeartbeatMonitor()
        emitter = PeriodicHeartbeatEmitter(
            component_id="projection_engine",
            monitor=monitor,
            interval_s=10.0,
        )
        await emitter.start()
        # ...
        await emitter.stop()
    """

    def __init__(
        self,
        component_id: str,
        monitor: HeartbeatMonitor,
        interval_s: float = 30.0,
        metadata_factory: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self._component_id = component_id
        self._monitor = monitor
        self._interval_s = interval_s
        self._metadata_factory = metadata_factory or (lambda: {})
        self._sequence: int = 0
        self._task: asyncio.Task[None] | None = None
        self._running: bool = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(
            self._loop(),
            name=f"heartbeat:{self._component_id}",
        )

    async def stop(self) -> None:
        self._running = False
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        self._task = None

    async def beat(self) -> Heartbeat:
        """Emit a single heartbeat immediately."""
        self._sequence += 1
        beat = Heartbeat(
            component_id=self._component_id,
            beat_at=_utc_now(),
            sequence=self._sequence,
            metadata=self._metadata_factory(),
        )
        self._monitor.record(beat)
        return beat

    @property
    def component_id(self) -> str:
        return self._component_id

    @property
    def is_alive(self) -> bool:
        return self._monitor.is_alive(self._component_id, self._interval_s * 2)

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.beat()
                await asyncio.sleep(self._interval_s)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(self._interval_s)


def make_heartbeat_health_checker(
    component_id: str,
    component_type: str,
    monitor: HeartbeatMonitor,
    max_age_s: float,
) -> Callable[[], Awaitable[ComponentHealth]]:
    """Create a health checker that surfaces missed heartbeats as UNHEALTHY."""
    async def _check() -> ComponentHealth:
        alive = monitor.is_alive(component_id, max_age_s)
        age = monitor.age_s(component_id)
        return ComponentHealth(
            component_id=component_id,
            component_type=component_type,
            status=HealthStatus.HEALTHY if alive else HealthStatus.UNHEALTHY,
            message="alive" if alive else (
                f"no heartbeat for {age:.1f}s (max={max_age_s}s)"
                if age is not None else f"no heartbeat received (max={max_age_s}s)"
            ),
            checked_at=_utc_now(),
            details={"age_s": age, "max_age_s": max_age_s},
        )
    return _check
