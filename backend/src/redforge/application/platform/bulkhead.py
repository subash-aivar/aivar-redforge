"""Bulkhead isolation — Sprint 26.

Limits the number of concurrent calls to a dependency so that a slow
or failing dependency cannot consume all available resources (threads,
connections, memory) and cascade failures to other components.

Named after the ship's bulkhead pattern: water flooding one compartment
does not sink the ship because each compartment is isolated.

Bulkhead vs Circuit Breaker:
- Circuit breaker: stops calls after too many failures.
- Bulkhead: limits concurrent calls regardless of failure rate.
- They compose: circuit breaker wraps bulkhead for defense-in-depth.

Design rules:
- No infrastructure imports.
- asyncio.Semaphore for wait queue (backpressure-aware).
- BulkheadFullError raised if max_wait_duration_s exceeded.
- release() always in finally block — never held across I/O boundaries.
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class BulkheadFullError(Exception):
    """Raised when a call cannot acquire a bulkhead slot within the wait limit."""

    def __init__(self, bulkhead_id: str, max_concurrent: int) -> None:
        super().__init__(
            f"Bulkhead {bulkhead_id!r} is full "
            f"(max_concurrent={max_concurrent}) — call rejected"
        )
        self.bulkhead_id = bulkhead_id
        self.max_concurrent = max_concurrent


@dataclasses.dataclass(frozen=True, slots=True)
class BulkheadConfig:
    max_concurrent: int = 10
    max_wait_duration_s: float = 5.0
    bulkhead_id: str = "default"

    def __post_init__(self) -> None:
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        if self.max_wait_duration_s < 0:
            raise ValueError("max_wait_duration_s must be >= 0")


@dataclasses.dataclass(frozen=True, slots=True)
class BulkheadStats:
    bulkhead_id: str
    max_concurrent: int
    active_calls: int
    total_calls: int
    rejected_calls: int
    available_slots: int


class SemaphoreBulkhead:
    """Semaphore-backed bulkhead with optional wait timeout.

    Usage::

        bulkhead = SemaphoreBulkhead(BulkheadConfig(
            bulkhead_id="knowledge_graph",
            max_concurrent=5,
            max_wait_duration_s=2.0,
        ))

        result = await bulkhead.execute(lambda: kg.query(subject_id))
    """

    def __init__(self, config: BulkheadConfig | None = None) -> None:
        self._cfg = config or BulkheadConfig()
        self._sem = asyncio.Semaphore(self._cfg.max_concurrent)
        self._lock = threading.Lock()
        self._active_calls: int = 0
        self._total_calls: int = 0
        self._rejected_calls: int = 0

    async def execute(self, coro_factory: Callable[[], Awaitable[Any]]) -> Any:
        """Acquire a slot, run the coroutine, release the slot.

        Raises BulkheadFullError if a slot cannot be acquired within
        max_wait_duration_s.
        """
        acquired = False
        with self._lock:
            self._total_calls += 1

        try:
            acquired = await asyncio.wait_for(
                self._sem.acquire(),
                timeout=self._cfg.max_wait_duration_s,
            )
        except TimeoutError:
            with self._lock:
                self._rejected_calls += 1
            raise BulkheadFullError(
                self._cfg.bulkhead_id,
                self._cfg.max_concurrent,
            ) from None

        with self._lock:
            self._active_calls += 1

        try:
            return await coro_factory()
        finally:
            with self._lock:
                self._active_calls = max(0, self._active_calls - 1)
            if acquired:
                self._sem.release()

    @property
    def active_calls(self) -> int:
        with self._lock:
            return self._active_calls

    @property
    def available_slots(self) -> int:
        with self._lock:
            return max(0, self._cfg.max_concurrent - self._active_calls)

    @property
    def is_full(self) -> bool:
        with self._lock:
            return self._active_calls >= self._cfg.max_concurrent

    def stats(self) -> BulkheadStats:
        with self._lock:
            return BulkheadStats(
                bulkhead_id=self._cfg.bulkhead_id,
                max_concurrent=self._cfg.max_concurrent,
                active_calls=self._active_calls,
                total_calls=self._total_calls,
                rejected_calls=self._rejected_calls,
                available_slots=max(0, self._cfg.max_concurrent - self._active_calls),
            )


class BulkheadRegistry:
    """Thread-safe registry of named bulkheads.

    Provides a single place to manage all bulkheads across the runtime.
    Each dependency (KG, EventStore, Connector, Campaign) should have its own.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._bulkheads: dict[str, SemaphoreBulkhead] = {}

    def register(self, name: str, bulkhead: SemaphoreBulkhead) -> None:
        with self._lock:
            self._bulkheads[name] = bulkhead

    def get(self, name: str) -> SemaphoreBulkhead | None:
        with self._lock:
            return self._bulkheads.get(name)

    def get_or_create(
        self,
        name: str,
        max_concurrent: int = 10,
        max_wait_duration_s: float = 5.0,
    ) -> SemaphoreBulkhead:
        with self._lock:
            if name not in self._bulkheads:
                self._bulkheads[name] = SemaphoreBulkhead(
                    BulkheadConfig(
                        bulkhead_id=name,
                        max_concurrent=max_concurrent,
                        max_wait_duration_s=max_wait_duration_s,
                    )
                )
            return self._bulkheads[name]

    def all_stats(self) -> dict[str, BulkheadStats]:
        with self._lock:
            return {name: bh.stats() for name, bh in self._bulkheads.items()}

    def list_names(self) -> list[str]:
        with self._lock:
            return list(self._bulkheads.keys())
