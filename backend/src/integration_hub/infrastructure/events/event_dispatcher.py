"""Minimal in-process domain event dispatcher (Phase 2C, P0-5).

`container.event_sink` used to be a plain `list[object]` that discovery
and health-check events (`AssetDiscovered`, `SyncRunCompleted`,
`ConnectorHealthDegraded`, ...) were appended/extended into with nothing
anywhere reading them back — the pipeline was structurally inert.

This module wires a real (but deliberately small) dispatcher in its
place: still list-shaped (so every existing `self._events.append(...)`/
`.extend(...)` call site in the application services keeps working
unmodified), but every event added is also drained synchronously to any
subscribed handlers.

Not a message queue / outbox: a repo-wide check (`ai_posture`,
`analytics`, `reporting`, `credential_vault`, `exposure_reporting`, ...)
found no existing event-bus/outbox mechanism used for cross-context
integration anywhere in this platform — every cross-context integration
here is a direct in-process ACL adapter call. A synchronous in-process
dispatcher matches that existing style; a full broker/queue would be an
unwarranted new abstraction for what this phase actually needs (proof
the pipeline is alive, plus one real consumer).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

EventHandler = Callable[[Any], None]


class EventDispatcher(list[Any]):
    """Drop-in replacement for the old `event_sink: list[object]` that
    also dispatches to registered handlers as events arrive. Intentional
    list subclass — see module docstring."""

    def __init__(self) -> None:
        super().__init__()
        self._handlers: list[EventHandler] = []

    def subscribe(self, handler: EventHandler) -> None:
        self._handlers.append(handler)

    def append(self, event: Any) -> None:
        super().append(event)
        self._dispatch(event)

    def extend(self, events: Iterable[Any]) -> None:
        materialized = list(events)
        super().extend(materialized)
        for event in materialized:
            self._dispatch(event)

    def _dispatch(self, event: Any) -> None:
        for handler in self._handlers:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "integration_hub.event_dispatch_failed",
                    event_type=type(event).__name__,
                )


def log_event_handler(event: Any) -> None:
    """First real subscriber: structured telemetry for every domain event.
    Proves the dispatcher is alive without fabricating a Risk Engine or
    Compliance integration that doesn't exist elsewhere in this platform —
    if/when those consumers are built, they subscribe the same way."""
    logger.info(
        "integration_hub.domain_event",
        event_type=type(event).__name__,
        tenant_id=getattr(event, "tenant_id", None),
        aggregate_id=getattr(event, "aggregate_id", None),
    )
