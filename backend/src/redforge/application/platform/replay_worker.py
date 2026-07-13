"""DLQ Replay Worker — Sprint 28.

Background asyncio task that polls the dead letter queue for entries marked
as 'requeued' (via POST /runtime/dlq/{id}/requeue) and replays them by
calling an injected replay_fn.

Design rules:
- The worker is pure application logic — no infrastructure imports.
- replay_fn: Callable[[DeadLetterEntry], Awaitable[bool]] is injected by
  app.py so the worker is decoupled from event store and projection engine.
- max_concurrent controls parallelism via asyncio.Semaphore.
- On replay success: calls dlq.mark_replayed(entry_id).
- On replay failure: leaves entry in 'requeued' state; retried next poll.
- Poison loop prevention: if an entry has been retried > replay_max_retries
  times, it is left in 'requeued' but skipped (logged as stuck).
- CancelledError propagates cleanly through stop().
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

from redforge.application.platform.runtime_contracts import DeadLetterEntry

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from redforge.application.platform.runtime_contracts import RuntimeDLQ


class DLQReplayWorker:
    """Polls the DLQ and replays requeued entries via an injected replay_fn.

    Args:
        dlq: Dead letter queue implementing the RuntimeDLQ protocol.
        replay_fn: Coroutine that attempts to replay one entry. Returns
            True on success, False on failure. Must NOT raise — exceptions
            are caught and treated as failure.
        poll_interval_s: Seconds to sleep when the DLQ is empty.
        max_concurrent: Maximum parallel replay coroutines per poll.
        batch_size: Maximum entries fetched per poll cycle.
        replay_max_retries: Entries with retry_count > this value are
            skipped (logged as stuck) to prevent infinite replay loops.
    """

    def __init__(
        self,
        dlq: RuntimeDLQ,
        replay_fn: Callable[[DeadLetterEntry], Awaitable[bool]],
        poll_interval_s: float = 5.0,
        max_concurrent: int = 5,
        batch_size: int = 10,
        replay_max_retries: int = 3,
    ) -> None:
        self._dlq = dlq
        self._replay_fn = replay_fn
        self._poll_interval_s = poll_interval_s
        self._max_concurrent = max_concurrent
        self._batch_size = batch_size
        self._replay_max_retries = replay_max_retries
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._replayed = 0
        self._failed = 0
        self._skipped = 0
        self._exhausted = 0

    @property
    def is_running(self) -> bool:
        """True when the background poll loop is active."""
        return self._running and self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Start the background poll loop."""
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name="dlq-replay-worker")

    async def stop(self) -> None:
        """Stop the background poll loop gracefully."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    def stats(self) -> dict[str, int | str]:
        """Return cumulative replay statistics including worker state."""
        return {
            "replayed": self._replayed,
            "failed": self._failed,
            "skipped": self._skipped,
            "exhausted": self._exhausted,
            "state": "running" if self.is_running else "stopped",
        }

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                processed = await self._poll_once()
                if processed == 0:
                    await asyncio.sleep(self._poll_interval_s)
            except asyncio.CancelledError:
                break
            except Exception:
                # Don't let unexpected errors kill the worker; back off and retry
                await asyncio.sleep(self._poll_interval_s)

    async def _poll_once(self) -> int:
        entries: Sequence[DeadLetterEntry] = await self._dlq.list_pending_replay(
            max_count=self._batch_size
        )
        if not entries:
            return 0

        sem = asyncio.Semaphore(self._max_concurrent)

        async def _bounded(entry: DeadLetterEntry) -> Any:
            async with sem:
                return await self._replay_one(entry)

        await asyncio.gather(*[_bounded(e) for e in entries], return_exceptions=True)
        return len(entries)

    async def _replay_one(self, entry: DeadLetterEntry) -> bool:
        # Entries that exceed the retry limit are moved to terminal exhausted state.
        if entry.retry_count > self._replay_max_retries:
            with contextlib.suppress(Exception):
                await self._dlq.mark_exhausted(entry.entry_id)
            self._exhausted += 1
            return False

        try:
            success = bool(await self._replay_fn(entry))
        except Exception:
            success = False

        if success:
            with contextlib.suppress(Exception):
                await self._dlq.mark_replayed(entry.entry_id)
            self._replayed += 1
        else:
            # Return the entry to requeued state so it can be retried.
            with contextlib.suppress(Exception):
                await self._dlq.release_inflight(entry.entry_id)
            self._failed += 1

        return success
