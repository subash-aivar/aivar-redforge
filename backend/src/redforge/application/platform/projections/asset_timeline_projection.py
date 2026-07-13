"""AssetTimelineProjection — per-asset event timeline read model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import AssetTimelineReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


_ASSET_EVENT_TYPES = frozenset({
    "inventory.AIAssetCreated",
    "inventory.AIAssetUpdated",
    "inventory.AIAssetArchived",
    "connector.DiscoveryJobCompleted",
    "connector.SyncJobCompleted",
    "validation.ValidationRunStarted",
    "validation.ValidationRunCompleted",
    "evidence.EvidenceCreated",
    "findings.FindingCreated",
    "asset.AssetRegistered",
    "asset.AssetObserved",
})


class AssetTimelineProjection(ProjectionBase):
    """Maintains per-asset event statistics for fast timeline queries."""

    projection_name = "asset_timeline"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._total: dict[str, int] = {}
        self._first_seen: dict[str, datetime | None] = {}
        self._last_seen: dict[str, datetime | None] = {}
        self._by_type: dict[str, dict[str, int]] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        for et in _ASSET_EVENT_TYPES:
            engine.register(self.projection_name, et, self._handle)

    def _asset_key(self, org: str, asset_id: str) -> str:
        return f"{org}:{asset_id}"

    def _init_asset(self, key: str) -> None:
        if key not in self._total:
            self._total[key] = 0
            self._first_seen[key] = None
            self._last_seen[key] = None
            self._by_type[key] = {}

    async def _handle(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        asset_id = envelope.aggregate_id
        key = self._asset_key(org, asset_id)
        self._init_asset(key)
        self._total[key] += 1
        if self._first_seen[key] is None:
            self._first_seen[key] = envelope.occurred_at
        self._last_seen[key] = envelope.occurred_at
        self._by_type[key][envelope.event_type] = (
            self._by_type[key].get(envelope.event_type, 0) + 1
        )
        self._last_positions[key] = envelope.global_position
        await self._persist(org, asset_id, key)

    async def _persist(self, org: str, asset_id: str, key: str) -> None:
        model = AssetTimelineReadModel(
            organization_id=org,
            asset_id=asset_id,
            total_events=self._total.get(key, 0),
            first_seen_at=self._first_seen.get(key),
            last_seen_at=self._last_seen.get(key),
            event_type_counts=dict(self._by_type.get(key, {})),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(key, 0),
        )
        await self._repo.save(model)

    async def get(
        self, organization_id: str, asset_id: str
    ) -> AssetTimelineReadModel | None:
        loaded = await self._repo.load("asset_timeline", organization_id)
        return cast("AssetTimelineReadModel | None", loaded)

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)
