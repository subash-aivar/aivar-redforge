"""InventoryProjection — tracks AI asset counts and discovery activity."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import InventoryReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


_INVENTORY_EVENT_PREFIXES = (
    "inventory.",
    "connector.",
    "ai_asset.",
    "asset.",
)


class InventoryProjection(ProjectionBase):
    """Tracks total assets, breakdown by type/status, and last discovery time."""

    projection_name = "inventory"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._by_type: dict[str, dict[str, int]] = {}
        self._by_status: dict[str, dict[str, int]] = {}
        self._total: dict[str, int] = {}
        self._recent: dict[str, list[str]] = {}
        self._last_discovery: dict[str, datetime | None] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        engine.register(self.projection_name, "inventory.AIAssetCreated", self._handle_created)
        engine.register(self.projection_name, "inventory.AIAssetUpdated", self._handle_updated)
        engine.register(self.projection_name, "inventory.AIAssetArchived", self._handle_archived)
        engine.register(
            self.projection_name,
            "connector.ConnectorDiscoveredAssets",
            self._handle_discovery,
        )
        engine.register(self.projection_name, "asset.AssetRegistered", self._handle_created)

    async def _handle_created(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        asset_id = envelope.aggregate_id
        asset_type = envelope.metadata.get_custom("asset_type") or "unknown"
        status = envelope.metadata.get_custom("status") or "active"
        self._by_type[org][asset_type] = self._by_type[org].get(asset_type, 0) + 1
        self._by_status[org][status] = self._by_status[org].get(status, 0) + 1
        self._total[org] = self._total.get(org, 0) + 1
        recent = self._recent[org]
        recent.append(asset_id)
        if len(recent) > 10:
            recent.pop(0)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_updated(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_archived(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        status = envelope.metadata.get_custom("status") or "archived"
        self._by_status[org][status] = self._by_status[org].get(status, 0) + 1
        active = self._by_status[org].get("active", 0)
        if active > 0:
            self._by_status[org]["active"] = active - 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_discovery(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._last_discovery[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    def _init_org(self, org: str) -> None:
        if org not in self._by_type:
            self._by_type[org] = {}
            self._by_status[org] = {}
            self._recent[org] = []
            self._last_discovery[org] = None
            self._total[org] = 0

    async def _persist(self, org: str) -> None:
        model = InventoryReadModel(
            organization_id=org,
            total_assets=self._total.get(org, 0),
            assets_by_type=dict(self._by_type.get(org, {})),
            assets_by_status=dict(self._by_status.get(org, {})),
            recently_discovered=tuple(self._recent.get(org, [])),
            last_discovery_at=self._last_discovery.get(org),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> InventoryReadModel | None:
        loaded = await self._repo.load("inventory", organization_id)
        return cast("InventoryReadModel | None", loaded)

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)
