"""Projection Supervisor and Worker Supervisor — Sprint 26.

Supervisors manage the lifecycle of long-running async components,
restarting them on failure with exponential backoff, detecting poison
events, and escalating to DLQ when recovery is exhausted.

Inspired by Erlang/OTP supervision trees and Kubernetes restart policies
but implemented as pure Python asyncio — no external dependencies.

Restart policy (OTP-style):
    attempt 1: restart after base_delay_s
    attempt 2: restart after base_delay_s * 2
    attempt N: restart after min(base_delay_s * 2^(N-1), max_delay_s)
    After max_restarts: escalate (mark FAILED, alert caller via callback).

Poison event detection (via PoisonEventDetector):
    When the same event_id fails >= poison_threshold times, it is routed
    to the DLQ and the projection skips it on next run.

Design rules:
- No infrastructure imports.
- No direct asyncio.Task manipulation outside _run_worker().
- Supervisors do not own event stores — they coordinate the engine.
- All mutable state under threading.Lock (safe with asyncio tasks).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.application.platform.runtime_contracts import (
    ProjectionHealth,
    WorkerHealth,
    WorkerState,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ── Worker descriptor ──────────────────────────────────────────────────────


@dataclasses.dataclass
class _WorkerEntry:
    worker_id: str
    factory: Callable[[], Awaitable[None]]
    max_restarts: int
    base_delay_s: float
    max_delay_s: float
    state: WorkerState = WorkerState.STOPPED
    restart_count: int = 0
    last_started_at: datetime | None = None
    last_failed_at: datetime | None = None
    error_message: str | None = None
    _task: asyncio.Task[None] | None = None


# ── Worker Supervisor ──────────────────────────────────────────────────────


class DefaultWorkerSupervisor:
    """Supervises async worker coroutines with restart and backoff.

    Workers are registered by name with a factory callable that produces
    the coroutine to run. On failure the factory is called again for each
    restart attempt (allows re-initialisation).

    Usage::

        supervisor = DefaultWorkerSupervisor(max_restarts=5)
        supervisor.register_worker(
            "projection_catch_up",
            factory=lambda: engine.catch_up(store, org_id),
        )
        await supervisor.start_worker("projection_catch_up")
    """

    def __init__(
        self,
        max_restarts: int = 5,
        base_delay_s: float = 1.0,
        max_delay_s: float = 60.0,
        on_exhausted: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._default_max_restarts = max_restarts
        self._default_base_delay_s = base_delay_s
        self._default_max_delay_s = max_delay_s
        self._on_exhausted = on_exhausted
        self._lock = threading.Lock()
        self._workers: dict[str, _WorkerEntry] = {}

    def register_worker(
        self,
        worker_id: str,
        factory: Callable[[], Awaitable[None]],
        max_restarts: int | None = None,
        base_delay_s: float | None = None,
        max_delay_s: float | None = None,
    ) -> None:
        with self._lock:
            self._workers[worker_id] = _WorkerEntry(
                worker_id=worker_id,
                factory=factory,
                max_restarts=max_restarts
                    if max_restarts is not None else self._default_max_restarts,
                base_delay_s=base_delay_s
                    if base_delay_s is not None else self._default_base_delay_s,
                max_delay_s=max_delay_s
                    if max_delay_s is not None else self._default_max_delay_s,
            )

    async def start_worker(self, worker_id: str) -> None:
        with self._lock:
            entry = self._workers.get(worker_id)
        if entry is None:
            raise KeyError(f"Worker not registered: {worker_id!r}")
        with self._lock:
            if entry.state == WorkerState.RUNNING:
                return
            entry.state = WorkerState.STARTING
            entry.last_started_at = _utc_now()
        task = asyncio.create_task(
            self._run_worker(entry),
            name=f"supervisor:{worker_id}",
        )
        with self._lock:
            entry._task = task
            entry.state = WorkerState.RUNNING

    async def stop_worker(self, worker_id: str) -> None:
        with self._lock:
            entry = self._workers.get(worker_id)
        if entry is None:
            return
        with self._lock:
            entry.state = WorkerState.STOPPING
            task = entry._task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(task), timeout=5.0)
        with self._lock:
            entry.state = WorkerState.STOPPED
            entry._task = None

    async def restart_worker(self, worker_id: str) -> None:
        await self.stop_worker(worker_id)
        with self._lock:
            entry = self._workers.get(worker_id)
            if entry is not None:
                entry.restart_count = 0
        await self.start_worker(worker_id)

    async def worker_health(self, worker_id: str) -> WorkerHealth:
        with self._lock:
            entry = self._workers.get(worker_id)
        if entry is None:
            return WorkerHealth(
                worker_id=worker_id,
                state=WorkerState.STOPPED,
                restart_count=0,
                last_started_at=None,
                last_failed_at=None,
                error_message=f"Worker {worker_id!r} not registered",
            )
        with self._lock:
            return WorkerHealth(
                worker_id=entry.worker_id,
                state=entry.state,
                restart_count=entry.restart_count,
                last_started_at=entry.last_started_at,
                last_failed_at=entry.last_failed_at,
                error_message=entry.error_message,
            )

    def list_workers(self) -> list[str]:
        with self._lock:
            return list(self._workers.keys())

    async def _run_worker(self, entry: _WorkerEntry) -> None:
        while True:
            try:
                await entry.factory()
                with self._lock:
                    entry.state = WorkerState.STOPPED
                return
            except asyncio.CancelledError:
                with self._lock:
                    entry.state = WorkerState.STOPPED
                return
            except Exception as exc:
                with self._lock:
                    entry.last_failed_at = _utc_now()
                    entry.error_message = str(exc)
                    entry.restart_count += 1
                    restarts = entry.restart_count
                    max_r = entry.max_restarts
                    base = entry.base_delay_s
                    max_d = entry.max_delay_s

                if restarts > max_r:
                    with self._lock:
                        entry.state = WorkerState.FAILED
                    if self._on_exhausted is not None:
                        await self._on_exhausted(entry.worker_id)
                    return

                delay = min(base * (2 ** (restarts - 1)), max_d)
                with self._lock:
                    entry.state = WorkerState.RESTARTING
                await asyncio.sleep(delay)
                with self._lock:
                    entry.state = WorkerState.RUNNING
                    entry.last_started_at = _utc_now()


# ── Projection Supervisor ──────────────────────────────────────────────────


@dataclasses.dataclass
class _ProjectionEntry:
    projection_name: str
    state: WorkerState = WorkerState.STOPPED
    restart_count: int = 0
    last_event_position: int = -1
    poison_event_count: int = 0
    last_failed_at: datetime | None = None
    error_message: str | None = None


class DefaultProjectionSupervisor:
    """Supervises named projections.

    Tracks: restart count, last processed position, poison event count,
    and failure escalation status. Does not directly interact with the
    projection engine — callers hook into the supervisor's callbacks to
    wire restart logic.

    Poison event handling:
        When is_poison_event() returns True, the caller should route to DLQ
        and call record_poison_skip() to skip the event without restarting.

    Usage::

        supervisor = DefaultProjectionSupervisor(max_restarts=3)
        supervisor.register("campaign_summary")

        try:
            await engine.process(envelope)
            supervisor.record_success("campaign_summary", envelope.global_position)
        except ProjectionError as e:
            if supervisor.is_poison_event("campaign_summary", envelope.event_id, 3):
                await dlq.store(make_dlq_entry(envelope, e))
                supervisor.record_poison_skip("campaign_summary")
            else:
                supervisor.record_failure("campaign_summary", str(e))
                await supervisor.maybe_restart("campaign_summary")
    """

    def __init__(self, max_restarts: int = 5) -> None:
        self._max_restarts = max_restarts
        self._lock = threading.Lock()
        self._projections: dict[str, _ProjectionEntry] = {}
        self._failure_counts: dict[tuple[str, str], int] = {}

    def register(self, projection_name: str) -> None:
        with self._lock:
            if projection_name not in self._projections:
                self._projections[projection_name] = _ProjectionEntry(
                    projection_name=projection_name
                )

    def record_success(self, projection_name: str, global_position: int) -> None:
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is not None:
                entry.last_event_position = global_position
                entry.error_message = None
                entry.state = WorkerState.RUNNING

    def record_failure(self, projection_name: str, error_message: str) -> None:
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is not None:
                entry.last_failed_at = _utc_now()
                entry.error_message = error_message

    def record_poison_skip(self, projection_name: str) -> None:
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is not None:
                entry.poison_event_count += 1

    def record_event_failure(
        self, projection_name: str, event_id: str
    ) -> int:
        """Track per-event failure count. Returns current count."""
        key = (projection_name, event_id)
        with self._lock:
            count = self._failure_counts.get(key, 0) + 1
            self._failure_counts[key] = count
            return count

    def is_poison_event(
        self,
        projection_name: str,
        event_id: str,
        poison_threshold: int = 3,
    ) -> bool:
        key = (projection_name, event_id)
        with self._lock:
            return self._failure_counts.get(key, 0) >= poison_threshold

    def reset_event_failures(self, projection_name: str, event_id: str) -> None:
        key = (projection_name, event_id)
        with self._lock:
            self._failure_counts.pop(key, None)

    async def start(self, projection_name: str) -> None:
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is None:
                return
            entry.state = WorkerState.RUNNING

    async def stop(self, projection_name: str) -> None:
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is None:
                return
            entry.state = WorkerState.STOPPED

    async def restart(self, projection_name: str) -> None:
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is None:
                return
            if entry.restart_count >= self._max_restarts:
                entry.state = WorkerState.FAILED
                return
            entry.restart_count += 1
            entry.state = WorkerState.RESTARTING
        await asyncio.sleep(0)
        with self._lock:
            if entry is not None:
                entry.state = WorkerState.RUNNING

    async def maybe_restart(self, projection_name: str) -> bool:
        """Restart if under max_restarts limit. Returns True if restarted."""
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is None:
                return False
            if entry.restart_count >= self._max_restarts:
                entry.state = WorkerState.FAILED
                return False
        await self.restart(projection_name)
        return True

    def is_exhausted(self, projection_name: str) -> bool:
        with self._lock:
            entry = self._projections.get(projection_name)
            if entry is None:
                return False
            return entry.restart_count >= self._max_restarts

    async def health(self, projection_name: str) -> ProjectionHealth:
        with self._lock:
            entry = self._projections.get(projection_name)
        if entry is None:
            return ProjectionHealth(
                projection_name=projection_name,
                state=WorkerState.STOPPED,
                restart_count=0,
                last_event_position=-1,
                poison_event_count=0,
                last_failed_at=None,
                error_message=f"Projection {projection_name!r} not registered",
            )
        with self._lock:
            return ProjectionHealth(
                projection_name=entry.projection_name,
                state=entry.state,
                restart_count=entry.restart_count,
                last_event_position=entry.last_event_position,
                poison_event_count=entry.poison_event_count,
                last_failed_at=entry.last_failed_at,
                error_message=entry.error_message,
            )

    def list_projections(self) -> list[str]:
        with self._lock:
            return list(self._projections.keys())
