"""RuntimeHealthTransitionWorker — M15.

Background asyncio task polling runtime health and recording genuine
transitions, mirroring `application/continuous_validation/
scheduler_worker.py` / `application/platform/replay_worker.py`'s own
lifecycle shape exactly (start()/stop()/is_running/stats(), bounded
poll loop, exception-isolated per-cycle continuation).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.application.security_operations.runtime_health_projector import (
        RuntimeHealthTransitionProjector,
    )

logger = logging.getLogger(__name__)


class RuntimeHealthTransitionWorker:
    def __init__(
        self,
        projector: RuntimeHealthTransitionProjector,
        poll_interval_s: float = 30.0,
    ) -> None:
        self._projector = projector
        self._poll_interval_s = poll_interval_s
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._cycles = 0
        self._transitions_recorded = 0

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(
            self._poll_loop(), name="runtime-health-transition-worker",
        )

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    def stats(self) -> dict[str, int | str]:
        return {
            "cycles": self._cycles,
            "transitions_recorded": self._transitions_recorded,
            "state": "running" if self.is_running else "stopped",
        }

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                transitions = await self._projector.check_and_record_transitions()
                self._transitions_recorded += len(transitions)
                self._cycles += 1
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("runtime health transition worker: poll cycle failed")
            await asyncio.sleep(self._poll_interval_s)
