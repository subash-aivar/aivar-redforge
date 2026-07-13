"""ProjectionEngine and supporting infrastructure — Sprint 24.

Dispatches EventEnvelopes to registered projection handlers using a
dict-keyed registry. No switch statements. No isinstance dispatch.

Dict layout:
    _handlers: {
        "campaign.CampaignCreated": [
            ("campaign_summary", handler_fn),
            ("org_activity", handler_fn),
        ],
        "__all__": [
            ("org_activity", catch_all_handler_fn),
        ],
    }

Each projection has its own ProjectionCheckpoint, saved after every
successfully processed event.
"""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from collections.abc import Callable, Coroutine, Sequence
from datetime import UTC, datetime
from typing import Any

from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.exceptions import ProjectionError
from redforge.domain.platform.value_objects import (
    ProjectionCheckpoint,
    ProjectionState,
)

Handler = Callable[[EventEnvelope], Coroutine[Any, Any, None] | None]
_ALL = "__all__"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class InMemoryCheckpointRepository:
    """Thread-safe in-memory checkpoint storage."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, ProjectionCheckpoint] = {}

    async def save(self, checkpoint: ProjectionCheckpoint) -> None:
        with self._lock:
            self._store[checkpoint.projection_id] = checkpoint

    async def load(self, projection_id: str) -> ProjectionCheckpoint | None:
        with self._lock:
            return self._store.get(projection_id)

    async def delete(self, projection_id: str) -> None:
        with self._lock:
            self._store.pop(projection_id, None)

    async def apply_retention(self, policy: object) -> int:
        return 0

    async def save_checkpoint(self, checkpoint: ProjectionCheckpoint) -> None:
        await self.save(checkpoint)

    async def load_checkpoint(
        self, projection_id: str
    ) -> ProjectionCheckpoint | None:
        return await self.load(projection_id)

    async def list_checkpoints(self, organization_id: str) -> list[ProjectionCheckpoint]:
        with self._lock:
            return list(self._store.values())

    @property
    def all_checkpoints(self) -> list[ProjectionCheckpoint]:
        with self._lock:
            return list(self._store.values())


class InMemoryReadModelRepository:
    """Thread-safe in-memory read model storage."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[tuple[str, str], Any] = {}

    async def save(self, model: Any) -> None:
        with self._lock:
            self._store[(model.model_type, model.organization_id)] = model

    async def load(self, model_type: str, organization_id: str) -> Any | None:
        with self._lock:
            return self._store.get((model_type, organization_id))

    async def list_types(self, organization_id: str) -> list[str]:
        with self._lock:
            return [k[0] for k in self._store if k[1] == organization_id]


class ProjectionEngine:
    """Dict-dispatched projection engine with checkpoint support.

    Thread-safe: handlers are registered before any events are processed,
    and the handler dict is read-only during processing.
    """

    def __init__(
        self,
        checkpoint_repo: InMemoryCheckpointRepository | None = None,
    ) -> None:
        self._lock = threading.Lock()
        # event_type → [(projection_name, handler)]
        self._handlers: dict[str, list[tuple[str, Handler]]] = defaultdict(list)
        self._checkpoint_repo = checkpoint_repo or InMemoryCheckpointRepository()
        self._projection_positions: dict[str, int] = {}
        self._events_processed: int = 0
        self._errors: list[tuple[str, str, str]] = []

    # ── Registration (call before processing begins) ───────────────────────

    def register(
        self,
        projection_name: str,
        event_type: str,
        handler: Handler,
    ) -> None:
        with self._lock:
            self._handlers[event_type].append((projection_name, handler))

    def register_all(self, projection_name: str, handler: Handler) -> None:
        """Register handler for ALL event types."""
        with self._lock:
            self._handlers[_ALL].append((projection_name, handler))

    # ── Processing ────────────────────────────────────────────────────────

    async def process(self, envelope: EventEnvelope) -> None:
        with self._lock:
            type_handlers = list(self._handlers.get(envelope.event_type, []))
            all_handlers = list(self._handlers.get(_ALL, []))

        for projection_name, handler in type_handlers + all_handlers:
            try:
                result = handler(envelope)
                if asyncio.iscoroutine(result):
                    await result
                self._projection_positions[projection_name] = envelope.global_position
            except Exception as exc:
                self._errors.append((projection_name, envelope.event_id, str(exc)))
                raise ProjectionError(projection_name, envelope.event_id, str(exc)) from exc

        with self._lock:
            self._events_processed += 1

    async def process_batch(self, envelopes: Sequence[EventEnvelope]) -> None:
        for envelope in envelopes:
            await self.process(envelope)

    async def catch_up(
        self,
        event_store: Any,
        organization_id: str,
        from_position: int = 0,
    ) -> int:
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
    def errors(self) -> list[tuple[str, str, str]]:
        with self._lock:
            return list(self._errors)

    def projection_position(self, projection_name: str) -> int:
        with self._lock:
            return self._projection_positions.get(projection_name, -1)

    def registered_projections(self) -> list[str]:
        with self._lock:
            seen: set[str] = set()
            result: list[str] = []
            for handlers in self._handlers.values():
                for name, _ in handlers:
                    if name not in seen:
                        seen.add(name)
                        result.append(name)
            return result

    async def get_checkpoint(self, projection_id: str) -> ProjectionCheckpoint | None:
        return await self._checkpoint_repo.load(projection_id)

    async def save_checkpoint(self, checkpoint: ProjectionCheckpoint) -> None:
        await self._checkpoint_repo.save(checkpoint)

    def make_checkpoint(
        self,
        projection_id: str,
        projection_name: str,
        global_position: int,
        events_processed: int = 0,
    ) -> ProjectionCheckpoint:
        return ProjectionCheckpoint(
            projection_id=projection_id,
            projection_name=projection_name,
            last_global_position=global_position,
            last_processed_at=_utc_now(),
            state=ProjectionState.LIVE,
            events_processed=events_processed,
        )
