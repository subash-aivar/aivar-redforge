"""OrganizationActivityProjection — catch-all event counter per bounded context.

Handles ALL event types (register_all) to produce a high-level activity
summary for each organisation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import OrganizationActivityReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _bounded_context(event_type: str) -> str:
    parts = event_type.split(".")
    return parts[0] if len(parts) >= 2 else event_type


class OrganizationActivityProjection(ProjectionBase):
    """Counts events by bounded context for each organisation."""

    projection_name = "organization_activity"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        # org_id → {context: count}
        self._counts: dict[str, dict[str, int]] = {}
        self._last_activity: dict[str, datetime] = {}
        self._last_positions: dict[str, int] = {}
        self._user_ids: dict[str, set[str]] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        self._register_all(engine, self._handle)

    async def _handle(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        ctx = _bounded_context(envelope.event_type)
        if org not in self._counts:
            self._counts[org] = {}
            self._user_ids[org] = set()
        self._counts[org][ctx] = self._counts[org].get(ctx, 0) + 1
        self._last_activity[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        if envelope.metadata.actor_id:
            self._user_ids[org].add(envelope.metadata.actor_id)

        model = OrganizationActivityReadModel(
            organization_id=org,
            total_events=sum(self._counts[org].values()),
            events_by_bounded_context=dict(self._counts[org]),
            last_activity_at=self._last_activity[org],
            active_users=len(self._user_ids[org]),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions[org],
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> OrganizationActivityReadModel | None:
        loaded = await self._repo.load("organization_activity", organization_id)
        return cast("OrganizationActivityReadModel | None", loaded)

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)
