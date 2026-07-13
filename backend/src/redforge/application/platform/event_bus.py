"""InMemoryEventBus — synchronous fan-out publisher + subscriber.

Implements both PlatformEventPublisher and EventSubscriber in one object.
Handlers are called synchronously in registration order — this is intentional
for deterministic testing. Async handlers are awaited in sequence.

Production: swap for an async message-queue adapter (Kafka, Redis Streams,
etc.) that also implements the same two protocols.
"""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from collections.abc import Callable, Coroutine, Sequence
from typing import Any

from redforge.domain.platform.events import EventEnvelope

Handler = Callable[[EventEnvelope], Coroutine[Any, Any, None] | None]
_ALL = "__all__"


class InMemoryEventBus:
    """Thread-safe, synchronous fan-out event bus."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._publish_log: list[EventEnvelope] = []

    # ── Publisher interface ────────────────────────────────────────────────

    async def publish(self, envelopes: Sequence[EventEnvelope]) -> None:
        for envelope in envelopes:
            await self.publish_one(envelope)

    async def publish_one(self, envelope: EventEnvelope) -> None:
        with self._lock:
            self._publish_log.append(envelope)
            handlers = list(self._handlers.get(envelope.event_type, []))
            handlers += list(self._handlers.get(_ALL, []))

        for handler in handlers:
            result = handler(envelope)
            if asyncio.iscoroutine(result):
                await result

    # ── Subscriber interface ───────────────────────────────────────────────

    def subscribe(self, event_type: str, handler: Handler) -> None:
        with self._lock:
            self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        with self._lock:
            self._handlers[_ALL].append(handler)

    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        import contextlib
        with self._lock:
            handlers = self._handlers.get(event_type, [])
            with contextlib.suppress(ValueError):
                handlers.remove(handler)

    # ── Inspection (test support) ──────────────────────────────────────────

    @property
    def published(self) -> list[EventEnvelope]:
        with self._lock:
            return list(self._publish_log)

    def clear_log(self) -> None:
        with self._lock:
            self._publish_log.clear()

    @property
    def handler_count(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._handlers.values())
