"""Backpressure Controller — Sprint 26.

Controls flow between fast producers and slow consumers to prevent:
- Memory exhaustion from unbounded in-flight items.
- Projection engine overload during replay bursts.
- Worker queue overflow under sustained load.

Two implementations:
1. SemaphoreBackpressureController — token-bucket via asyncio.Semaphore.
   Blocks producers when all slots are taken.
2. WatermarkBackpressureController — high/low watermark hysteresis.
   Throttles producers above high watermark, resumes below low watermark.
   Adds adaptive delay instead of hard blocking.

Pacing helpers:
- ProjectionPacer — slows down catch-up replay to avoid overloading.
- ReplayPacer — adds per-batch delay during historical replay.

Design rules:
- No infrastructure imports.
- All blocking via asyncio primitives (not threading.Event).
- release() is sync (called from finally blocks in projection handlers).
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclasses.dataclass(frozen=True, slots=True)
class BackpressureConfig:
    """Configuration for the watermark-based controller."""

    max_concurrent: int = 1000
    high_watermark: float = 0.8
    low_watermark: float = 0.5
    throttle_delay_s: float = 0.01
    max_throttle_delay_s: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 < self.low_watermark < self.high_watermark <= 1.0:
            raise ValueError(
                "Watermarks must satisfy 0 < low < high <= 1"
            )
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")


class SemaphoreBackpressureController:
    """Hard-limit backpressure via asyncio.Semaphore.

    acquire() suspends the caller when all slots are occupied.
    release() must be called in a finally block or via context manager.

    Best for: projection handlers where bounded parallelism is required.
    """

    def __init__(self, max_concurrent: int = 100) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        self._max = max_concurrent
        self._sem = asyncio.Semaphore(max_concurrent)
        self._in_flight = 0
        self._lock = threading.Lock()

    async def acquire(self) -> None:
        await self._sem.acquire()
        with self._lock:
            self._in_flight += 1

    def release(self) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
        self._sem.release()

    @property
    def is_throttled(self) -> bool:
        with self._lock:
            return self._in_flight >= self._max

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return self._in_flight

    @property
    def available_slots(self) -> int:
        with self._lock:
            return max(0, self._max - self._in_flight)

    async def execute(self, coro_factory: object) -> object:
        """Acquire slot, run coroutine, release slot. Context-manager pattern."""
        fn: Callable[[], Awaitable[object]] = coro_factory  # type: ignore[assignment]
        await self.acquire()
        try:
            return await fn()
        finally:
            self.release()


class WatermarkBackpressureController:
    """Adaptive-delay backpressure using high/low watermark hysteresis.

    Does not block callers hard — instead applies an increasing delay
    when queue depth exceeds the high watermark. Resumes normal operation
    when depth drops below the low watermark.

    This is preferable for replay pacing where stalling the event loop
    would cause timeouts in other components.
    """

    def __init__(self, config: BackpressureConfig | None = None) -> None:
        self._cfg = config or BackpressureConfig()
        self._lock = threading.Lock()
        self._in_flight: int = 0
        self._throttled: bool = False

    async def acquire(self) -> None:
        with self._lock:
            self._in_flight += 1
            ratio = self._in_flight / self._cfg.max_concurrent
            if ratio >= self._cfg.high_watermark:
                self._throttled = True

        if self._throttled:
            delay = min(
                self._cfg.throttle_delay_s * (self._in_flight / self._cfg.max_concurrent),
                self._cfg.max_throttle_delay_s,
            )
            await asyncio.sleep(delay)

    def release(self) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
            ratio = self._in_flight / self._cfg.max_concurrent
            if ratio <= self._cfg.low_watermark:
                self._throttled = False

    @property
    def is_throttled(self) -> bool:
        with self._lock:
            return self._throttled

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return self._in_flight

    @property
    def utilization(self) -> float:
        with self._lock:
            return self._in_flight / self._cfg.max_concurrent


# ── Projection pacing ──────────────────────────────────────────────────────


class ProjectionPacer:
    """Rate-limits the projection catch-up loop to protect the event loop.

    Inserts a brief sleep every `batch_size` events processed.
    Prevents a large backlog replay from starving other coroutines.
    """

    def __init__(
        self,
        batch_size: int = 100,
        inter_batch_delay_s: float = 0.01,
    ) -> None:
        self._batch_size = batch_size
        self._inter_batch_delay_s = inter_batch_delay_s
        self._processed_since_pause: int = 0

    async def tick(self) -> None:
        """Call after each event. Sleeps at batch boundary."""
        self._processed_since_pause += 1
        if self._processed_since_pause >= self._batch_size:
            self._processed_since_pause = 0
            await asyncio.sleep(self._inter_batch_delay_s)

    def reset(self) -> None:
        self._processed_since_pause = 0

    @property
    def events_since_last_pause(self) -> int:
        return self._processed_since_pause


class ReplayPacer:
    """Adds per-page delay during historical event replay.

    Prevents the ReplayEngine from reading the entire event store
    in a tight loop that exhausts connection pool and memory.
    """

    def __init__(
        self,
        page_size: int = 500,
        inter_page_delay_s: float = 0.05,
    ) -> None:
        self._page_size = page_size
        self._inter_page_delay_s = inter_page_delay_s
        self._pages_processed: int = 0
        self._start_time: float = time.monotonic()

    async def page_processed(self, events_in_page: int) -> None:
        """Call after each page of events. Sleeps between pages."""
        self._pages_processed += 1
        if events_in_page >= self._page_size:
            await asyncio.sleep(self._inter_page_delay_s)

    @property
    def pages_processed(self) -> int:
        return self._pages_processed

    @property
    def elapsed_s(self) -> float:
        return time.monotonic() - self._start_time
