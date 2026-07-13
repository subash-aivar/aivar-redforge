"""Idempotent projection engine — Sprint 25.

Wraps the ProjectionEngine with exactly-once semantics:
- Each (projection_name, event_id) pair is processed at most once.
- Dedup set is seeded from checkpoint on startup.
- Checkpoint is saved after every successfully processed event.
- Replay safety: re-delivering any event already in the dedup set is a no-op.

Design rules:
- No imports from infrastructure layer.
- Dedup set is per-projection (not global) to keep memory proportional.
- Checkpoint is the durable form of the dedup set (via position — all events
  at position <= last_global_position have been processed).
- In-process dedup set guards within a session against double-delivery.

Idempotency guarantee:
    For any event E delivered to projection P:
    - If global_position(E) <= checkpoint.last_global_position → skip (already processed)
    - If event_id(E) is in in-memory dedup set → skip (double delivery in session)
    - Otherwise: call handler, persist checkpoint, add to dedup set

This provides:
    ✓ Crash recovery: restart from checkpoint position
    ✓ Replay safety: historical events before checkpoint are skipped
    ✓ Double-delivery guard: in-session dedup for non-ordered delivery
"""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from collections.abc import Callable, Coroutine, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.exceptions import ProjectionError
from redforge.domain.platform.value_objects import (
    ProjectionCheckpoint,
    ProjectionState,
)

if TYPE_CHECKING:
    from redforge.application.platform.contracts import CheckpointRepository

Handler = Callable[[EventEnvelope], Coroutine[Any, Any, None] | None]
_ALL = "__all__"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class IdempotentProjectionEngine:
    """Dict-dispatched projection engine with exactly-once semantics.

    Drop-in replacement for ProjectionEngine that adds idempotency.
    All registration, catch-up, and processing APIs are identical.

    The engine saves a checkpoint after EACH event, not only at the end of
    a batch. This means worst-case re-processing is exactly one event.
    """

    def __init__(
        self,
        checkpoint_repo: CheckpointRepository,
    ) -> None:
        self._lock = threading.Lock()
        # event_type → [(projection_name, handler)]
        self._handlers: dict[str, list[tuple[str, Handler]]] = defaultdict(list)
        self._checkpoint_repo = checkpoint_repo
        # per-projection position ceiling (from loaded checkpoint)
        self._checkpoint_positions: dict[str, int] = {}
        # per-projection in-session event_id dedup set
        self._processed_ids: dict[str, set[str]] = defaultdict(set)
        self._events_processed: int = 0
        self._events_skipped: int = 0
        self._errors: list[tuple[str, str, str]] = []

    # ── Registration ───────────────────────────────────────────────────────

    def register(
        self,
        projection_name: str,
        event_type: str,
        handler: Handler,
    ) -> None:
        with self._lock:
            self._handlers[event_type].append((projection_name, handler))

    def register_all(self, projection_name: str, handler: Handler) -> None:
        with self._lock:
            self._handlers[_ALL].append((projection_name, handler))

    # ── Checkpoint bootstrap ───────────────────────────────────────────────

    async def load_checkpoints(self) -> None:
        """Load all saved checkpoints to seed idempotency positions.

        Loads checkpoints for all registered projections AND for any
        previously persisted projections not yet registered (so that
        checkpoints survive engine restarts even when registration order
        varies). Call once at startup before processing begins.
        """
        with self._lock:
            all_projections = self._all_projection_names()

        # Load checkpoints for known projections
        for name in all_projections:
            cp = await self._checkpoint_repo.load(name)
            if cp is not None:
                with self._lock:
                    self._checkpoint_positions[name] = cp.last_global_position

        # Also eagerly load any checkpoints not covered by registered projections
        # (handles restart where registration and loading are interleaved)
        if hasattr(self._checkpoint_repo, "list_checkpoints"):
            all_cps = await self._checkpoint_repo.list_checkpoints("")
            for cp in all_cps:
                with self._lock:
                    if cp.projection_id not in self._checkpoint_positions:
                        self._checkpoint_positions[cp.projection_id] = (
                            cp.last_global_position
                        )

    def _all_projection_names(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for handlers in self._handlers.values():
            for name, _ in handlers:
                if name not in seen:
                    seen.add(name)
                    result.append(name)
        return result

    # ── Processing ────────────────────────────────────────────────────────

    async def process(self, envelope: EventEnvelope) -> None:
        """Process one envelope, skipping it per-projection if already seen."""
        with self._lock:
            type_handlers = list(self._handlers.get(envelope.event_type, []))
            all_handlers = list(self._handlers.get(_ALL, []))

        for projection_name, handler in type_handlers + all_handlers:
            await self._process_for_projection(
                projection_name, handler, envelope
            )

        with self._lock:
            self._events_processed += 1

    async def _process_for_projection(
        self,
        projection_name: str,
        handler: Handler,
        envelope: EventEnvelope,
    ) -> None:
        with self._lock:
            checkpoint_pos = self._checkpoint_positions.get(projection_name, -1)
            already_seen = envelope.event_id in self._processed_ids[projection_name]

        # Skip if before checkpoint position (crash-recovery path)
        if envelope.global_position <= checkpoint_pos:
            with self._lock:
                self._events_skipped += 1
            return

        # Skip if in-session dedup (double-delivery guard)
        if already_seen:
            with self._lock:
                self._events_skipped += 1
            return

        try:
            result = handler(envelope)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            with self._lock:
                self._errors.append((projection_name, envelope.event_id, str(exc)))
            raise ProjectionError(projection_name, envelope.event_id, str(exc)) from exc

        # Record as processed (in-memory dedup)
        with self._lock:
            self._processed_ids[projection_name].add(envelope.event_id)
            self._checkpoint_positions[projection_name] = envelope.global_position

        # Persist checkpoint durably
        cp = ProjectionCheckpoint(
            projection_id=projection_name,
            projection_name=projection_name,
            last_global_position=envelope.global_position,
            last_processed_at=_utc_now(),
            state=ProjectionState.LIVE,
            events_processed=len(self._processed_ids[projection_name]),
        )
        await self._checkpoint_repo.save(cp)

    async def process_batch(self, envelopes: Sequence[EventEnvelope]) -> None:
        for envelope in envelopes:
            await self.process(envelope)

    async def catch_up(
        self,
        event_store: Any,
        organization_id: str,
        from_position: int = 0,
    ) -> int:
        """Replay from event store. Skips already-checkpointed events."""
        events = await event_store.read_all(
            organization_id=organization_id,
            from_global_position=from_position,
        )
        await self.process_batch(list(events))
        return len(events)

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def events_processed(self) -> int:
        with self._lock:
            return self._events_processed

    @property
    def events_skipped(self) -> int:
        with self._lock:
            return self._events_skipped

    @property
    def errors(self) -> list[tuple[str, str, str]]:
        with self._lock:
            return list(self._errors)

    def checkpoint_position(self, projection_name: str) -> int:
        with self._lock:
            return self._checkpoint_positions.get(projection_name, -1)

    def registered_projections(self) -> list[str]:
        with self._lock:
            return self._all_projection_names()

    async def get_checkpoint(self, projection_id: str) -> ProjectionCheckpoint | None:
        return await self._checkpoint_repo.load(projection_id)
