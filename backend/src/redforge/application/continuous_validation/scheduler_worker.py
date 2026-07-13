"""ContinuousValidationSchedulerWorker — M14.

Background asyncio task polling for due ContinuousValidationPolicy rows
and dispatching them through ContinuousValidationProcessor. Mirrors
`application/platform/replay_worker.py`'s DLQReplayWorker lifecycle
shape exactly (start()/stop()/is_running/stats(), bounded poll loop,
exception-isolated per-cycle backoff) — the one other real, currently-
running background worker in this codebase.

Each poll attempts up to `batch_size` concurrent claims (bounded by
`max_concurrent` via semaphore); the atomic, SKIP LOCKED claim inside
`ContinuousValidationProcessor.process_one_due_policy()` already
guarantees concurrent attempts within (and across) worker instances
never claim the same due policy twice — see
`SqlAlchemyContinuousValidationPolicyRepository.claim_one_due_policy()`'s
own docstring. No busy loop: an empty cycle (nothing due) sleeps for
`poll_interval_s` before trying again.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.application.continuous_validation.processor import (
        ContinuousValidationProcessor,
    )

logger = logging.getLogger(__name__)


class ContinuousValidationSchedulerWorker:
    def __init__(
        self,
        processor: ContinuousValidationProcessor,
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
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(
            self._poll_loop(), name="continuous-validation-scheduler-worker",
        )

    async def stop(self) -> None:
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
                logger.exception("continuous validation scheduler: poll cycle failed")
                await asyncio.sleep(self._poll_interval_s)

    async def _poll_once(self) -> int:
        sem = asyncio.Semaphore(self._max_concurrent)

        async def _bounded_attempt() -> bool:
            async with sem:
                try:
                    execution = await self._processor.process_one_due_policy(self._worker_id)
                except Exception:
                    logger.exception("continuous validation scheduler: run attempt failed")
                    self._failed += 1
                    return False
                if execution is not None:
                    self._processed += 1
                    return True
                return False

        results = await asyncio.gather(*[_bounded_attempt() for _ in range(self._batch_size)])
        return sum(1 for r in results if r)
