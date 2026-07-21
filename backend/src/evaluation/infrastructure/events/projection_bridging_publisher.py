"""Bridges evaluation domain events into platform EventEnvelope projection handlers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from evaluation.application.ports.i_event_publisher import IEventPublisher
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.value_objects import CorrelationId, EventMetadata

if TYPE_CHECKING:
    from evaluation.domain.events.base import BaseDomainEvent

ProjectionHandler = Callable[[EventEnvelope], Awaitable[None]]


class ProjectionBridgingEventPublisher(IEventPublisher):
    """Publishes domain events to registered projection handlers for replay rebuild.

    Maps each domain event to an EventEnvelope whose event_type is the class name
    (matching ProjectionBase registrations). Handlers may be registered per type.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[ProjectionHandler]] = {}
        self._published: list[EventEnvelope] = []
        self._stream_positions: dict[str, int] = {}
        self._global_position = 0

    def register_handler(self, event_type: str, handler: ProjectionHandler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def register_projection(self, projection: Any) -> None:
        """Register a ProjectionBase instance via a tiny adapter engine."""

        class _Engine:
            def __init__(self, outer: ProjectionBridgingEventPublisher) -> None:
                self._outer = outer

            def register(
                self, projection_name: str, event_type: str, handler: ProjectionHandler
            ) -> None:
                self._outer.register_handler(event_type, handler)

        projection.register_with(_Engine(self))

    @property
    def published(self) -> list[EventEnvelope]:
        return list(self._published)

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        for event in events:
            envelope = self._to_envelope(event)
            self._published.append(envelope)
            for handler in self._handlers.get(type(event).__name__, []):
                await handler(envelope)

    def _to_envelope(self, event: BaseDomainEvent) -> EventEnvelope:
        stream_id = f"{event.aggregate_type}:{event.aggregate_id}"
        pos = self._stream_positions.get(stream_id, -1) + 1
        self._stream_positions[stream_id] = pos
        self._global_position += 1
        payload: object
        if is_dataclass(event) and not isinstance(event, type):
            payload = asdict(event)
        else:
            payload = vars(event)
        org = str(event.tenant_id)
        occurred = getattr(event, "occurred_at", None)
        if not isinstance(occurred, datetime):
            occurred = datetime.now(UTC)
        recorded = datetime.now(UTC)
        return EventEnvelope(
            event_id=str(getattr(event, "event_id", uuid4())),
            stream_id=stream_id,
            stream_position=pos,
            global_position=self._global_position,
            event_type=type(event).__name__,
            aggregate_type=event.aggregate_type,
            aggregate_id=str(event.aggregate_id),
            organization_id=org,
            payload=payload,
            metadata=EventMetadata(correlation_id=CorrelationId(str(uuid4()))),
            occurred_at=occurred,
            recorded_at=recorded,
        )
