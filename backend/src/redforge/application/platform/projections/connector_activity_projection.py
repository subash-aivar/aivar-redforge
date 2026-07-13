"""ConnectorActivityProjection — tracks connector discovery and sync activity."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import ConnectorActivityReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ConnectorActivityProjection(ProjectionBase):
    """Tracks connector counts and discovery/sync activity per organisation."""

    projection_name = "connector_activity"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._connector_ids: dict[str, set[str]] = {}
        self._active_ids: dict[str, set[str]] = {}
        self._discoveries: dict[str, int] = {}
        self._syncs: dict[str, int] = {}
        self._last_discovery: dict[str, datetime | None] = {}
        self._last_sync: dict[str, datetime | None] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        pn = self.projection_name
        engine.register(pn, "connector.ConnectorRegistered", self._handle_registered)
        engine.register(pn, "connector.ConnectorEnabled", self._handle_enabled)
        engine.register(pn, "connector.ConnectorDisabled", self._handle_disabled)
        engine.register(pn, "connector.ConnectorArchived", self._handle_archived)
        engine.register(pn, "connector.DiscoveryJobCompleted", self._handle_discovery)
        engine.register(pn, "connector.SyncJobCompleted", self._handle_sync)

    def _init_org(self, org: str) -> None:
        if org not in self._connector_ids:
            self._connector_ids[org] = set()
            self._active_ids[org] = set()
            self._discoveries[org] = 0
            self._syncs[org] = 0
            self._last_discovery[org] = None
            self._last_sync[org] = None

    async def _handle_registered(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._connector_ids[org].add(envelope.aggregate_id)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_enabled(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._connector_ids[org].add(envelope.aggregate_id)
        self._active_ids[org].add(envelope.aggregate_id)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_disabled(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._active_ids[org].discard(envelope.aggregate_id)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_archived(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._active_ids[org].discard(envelope.aggregate_id)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_discovery(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._discoveries[org] += 1
        self._last_discovery[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_sync(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._syncs[org] += 1
        self._last_sync[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _persist(self, org: str) -> None:
        model = ConnectorActivityReadModel(
            organization_id=org,
            total_connectors=len(self._connector_ids.get(org, set())),
            active_connectors=len(self._active_ids.get(org, set())),
            total_discoveries=self._discoveries.get(org, 0),
            total_syncs=self._syncs.get(org, 0),
            last_discovery_at=self._last_discovery.get(org),
            last_sync_at=self._last_sync.get(org),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> ConnectorActivityReadModel | None:
        loaded = await self._repo.load("connector_activity", organization_id)
        return cast("ConnectorActivityReadModel | None", loaded)

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)
