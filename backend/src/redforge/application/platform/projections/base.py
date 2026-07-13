"""ProjectionBase — shared infrastructure for all projection implementations.

Projections register event handlers with a ProjectionEngine using the
register() / register_all() pattern. Each projection also holds a reference
to a ReadModelRepository so it can persist its output.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from redforge.application.platform.projection_engine import (
    ProjectionEngine,
)
from redforge.domain.platform.events import EventEnvelope


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ProjectionBase:
    """Mixin that simplifies projection registration."""

    projection_name: str = ""

    def register_with(self, engine: ProjectionEngine) -> None:
        """Override to register all event handlers with the engine."""
        raise NotImplementedError

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        """Write the current in-memory read model to a durable repository.

        Called by the replay pipeline after engine.process() to persist the
        updated read model state to PostgreSQL within the same transaction.
        Default is a no-op; subclasses with in-memory state must override.

        Args:
            target_repo: A ReadModelRepository-compatible object (duck typing).
            organization_id: The org whose read model should be flushed.
        """

    def _register(
        self,
        engine: ProjectionEngine,
        event_type: str,
        handler: object,
    ) -> None:
        engine.register(self.projection_name, event_type, handler)  # type: ignore[arg-type]

    def _register_all(self, engine: ProjectionEngine, handler: object) -> None:
        engine.register_all(self.projection_name, handler)  # type: ignore[arg-type]

    def _envelope_to_key(self, envelope: EventEnvelope) -> str:
        return f"{envelope.aggregate_type}:{envelope.aggregate_id}"
