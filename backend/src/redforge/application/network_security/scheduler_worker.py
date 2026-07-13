"""NetworkMonitoringSchedulerWorker — M16.

Background asyncio task polling for due NetworkMonitoringPolicy rows and
dispatching them through NetworkMonitoringProcessor. Mirrors
`application/continuous_validation/scheduler_worker.py`'s
ContinuousValidationSchedulerWorker lifecycle shape exactly
(start()/stop()/is_running/stats(), bounded poll loop, exception-isolated
per-cycle backoff) — this is the SAME lifecycle idiom every other real
background worker in this codebase uses (DLQReplayWorker,
RuntimeHealthTransitionWorker), not a new pattern.

Each poll attempts up to `batch_size` concurrent claims (bounded by
`max_concurrent` via semaphore); the atomic SKIP LOCKED claim inside
`NetworkMonitoringProcessor.process_one_due_policy()` (and, beneath
that, `NetworkValidationOrchestrator.create_and_run()`'s fresh
per-address M10 authorization re-check) already guarantees:
  - concurrent attempts within/across worker instances never claim the
    same due policy twice (see
    SqlAlchemyNetworkMonitoringPolicyRepository.claim_one_due_policy()),
  - a policy whose authorization has since expired/been revoked is
    denied at execution time regardless of who claimed it.
No busy loop: an empty cycle (nothing due) sleeps for `poll_interval_s`
before trying again. No hidden global mutable state — all state is
instance attributes of one worker object, exactly one per process
(app.py creates and stores exactly one on `RuntimeContainer`).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.application.network_security.scheduler import NetworkMonitoringProcessor

logger = logging.getLogger(__name__)


class NetworkMonitoringSchedulerWorker:
    def __init__(
        self,
        processor: NetworkMonitoringProcessor,
        worker_id: str,
        poll_interval_s: float = 30.0,
        max_concurrent: int = 4,
        batch_size: int = 8,
    ) -> None:
        self._processor = processor
        self._worker_id = worker_id
        self._poll_interval_s = poll_interval_s
        self._max_concurrent = max_concurrent
        self._batch_size = batch_size
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._processed = 0
        self._failed = 0
        self._cycles = 0

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Idempotent-in-intent: calling start() while already running
        replaces nothing and creates no second task — callers (app.py)
        are responsible for calling this exactly once per process, but
        this guard prevents a duplicate task if it is ever called
        twice by mistake."""
        if self.is_running:
            return
        self._running = True
        self._task = asyncio.create_task(
            self._poll_loop(), name="network-monitoring-scheduler-worker",
        )

    async def stop(self) -> None:
        """Cancellation-safe: cancels the poll loop task and awaits it
        (swallowing CancelledError via return_exceptions=True) so
        shutdown never hangs waiting on an in-flight sleep, and never
        leaves an orphaned task behind."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    def stats(self) -> dict[str, int | str]:
        return {
            "processed": self._processed,
            "failed": self._failed,
            "cycles": self._cycles,
            "state": "running" if self.is_running else "stopped",
        }

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                processed = await self._poll_once()
                self._cycles += 1
                if processed == 0:
                    await asyncio.sleep(self._poll_interval_s)
            except asyncio.CancelledError:
                break
            except Exception:
                # Failure isolation: one cycle's unexpected exception
                # (e.g. a transient DB blip) never kills the poll loop
                # itself — logged, backed off, retried next cycle.
                logger.exception("network monitoring scheduler: poll cycle failed")
                await asyncio.sleep(self._poll_interval_s)

    async def _poll_once(self) -> int:
        sem = asyncio.Semaphore(self._max_concurrent)

        async def _bounded_attempt() -> bool:
            async with sem:
                try:
                    run = await self._processor.process_one_due_policy(self._worker_id)
                except Exception:
                    logger.exception("network monitoring scheduler: run attempt failed")
                    self._failed += 1
                    return False
                if run is not None:
                    self._processed += 1
                    return True
                return False

        results = await asyncio.gather(*[_bounded_attempt() for _ in range(self._batch_size)])
        return sum(1 for r in results if r)
