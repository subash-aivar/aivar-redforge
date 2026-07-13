"""Event publisher interface and in-memory implementation.

Domain events are collected by aggregates. After persistence succeeds,
the application layer publishes them through this interface. Implementations
can dispatch to message queues, webhooks, audit logs, or analytics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence


@runtime_checkable
class EventPublisher(Protocol):
    """Port for publishing domain events to downstream consumers."""

    async def publish(self, events: Sequence[object]) -> None:
        """Publish a batch of domain events."""
        ...


class InMemoryEventPublisher:
    """In-memory event publisher for testing and development."""

    def __init__(self) -> None:
        self.published: list[object] = []

    async def publish(self, events: Sequence[object]) -> None:
        self.published.extend(events)

    def clear(self) -> None:
        self.published.clear()


class NullEventPublisher:
    """No-op event publisher. Discards all events silently."""

    async def publish(self, events: Sequence[object]) -> None:
        pass
