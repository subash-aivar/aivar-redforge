from __future__ import annotations

from uuid import UUID

from integration_hub.domain.aggregates.discovered_asset import DiscoveredAsset
from integration_hub.domain.aggregates.sync_run import SyncRun
from integration_hub.domain.repositories.i_discovery_repositories import (
    IDiscoveredAssetRepository,
    ISyncRunRepository,
)
from integration_hub.domain.value_objects.discovery import AssetRelationship, SyncRunStatus
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class InMemoryDiscoveredAssetRepository(IDiscoveredAssetRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, DiscoveredAsset]] = {}

    async def save(self, asset: DiscoveredAsset, tenant_id: EntityId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(asset.asset_id)] = asset

    async def get(self, asset_id: UUID, tenant_id: EntityId) -> DiscoveredAsset | None:
        return self._items.get(str(tenant_id), {}).get(str(asset_id))

    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: EntityId
    ) -> DiscoveredAsset | None:
        for asset in self._items.get(str(tenant_id), {}).values():
            if asset.identity.fingerprint == fingerprint:
                return asset
        return None

    async def get_by_fingerprints(
        self, fingerprints: list[str], tenant_id: EntityId
    ) -> dict[str, DiscoveredAsset]:
        wanted = set(fingerprints)
        return {
            a.identity.fingerprint: a
            for a in self._items.get(str(tenant_id), {}).values()
            if a.identity.fingerprint in wanted
        }

    async def save_many(self, assets: list[DiscoveredAsset], tenant_id: EntityId) -> None:
        bucket = self._items.setdefault(str(tenant_id), {})
        for asset in assets:
            bucket[str(asset.asset_id)] = asset

    async def find_all_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId
    ) -> list[DiscoveredAsset]:
        return [
            a
            for a in self._items.get(str(tenant_id), {}).values()
            if a.connector_id.value == connector_id.value
        ]

    async def find_all_for_tenant(
        self,
        tenant_id: EntityId,
        *,
        category: str | None = None,
        vendor: str | None = None,
        tag: str | None = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "-discovered_at",
    ) -> list[DiscoveredAsset]:
        rows = list(self._items.get(str(tenant_id), {}).values())
        if category:
            rows = [a for a in rows if a.category.value == category]
        if vendor:
            rows = [a for a in rows if a.vendor.value == vendor]
        if tag:
            rows = [a for a in rows if tag in a.tags]
        field = order_by.lstrip("-")
        reverse = order_by.startswith("-")
        rows.sort(key=lambda a: getattr(a, field), reverse=reverse)
        return rows[offset : offset + limit]

    async def find_relationships_for_assets(
        self, asset_ids: list[UUID], tenant_id: EntityId
    ) -> dict[UUID, list[AssetRelationship]]:
        by_tenant = self._items.get(str(tenant_id), {})
        wanted = {str(i) for i in asset_ids}
        result: dict[UUID, list[AssetRelationship]] = {}
        for key, asset in by_tenant.items():
            if key in wanted:
                result[asset.asset_id] = list(asset.relationships)
        return result

    async def delete(self, asset_id: UUID, tenant_id: EntityId) -> None:
        self._items.get(str(tenant_id), {}).pop(str(asset_id), None)


class InMemorySyncRunRepository(ISyncRunRepository):
    def __init__(self) -> None:
        self._items: dict[str, list[SyncRun]] = {}

    async def save(self, run: SyncRun, tenant_id: EntityId) -> None:
        rows = self._items.setdefault(str(tenant_id), [])
        for i, existing in enumerate(rows):
            if existing.sync_run_id == run.sync_run_id:
                rows[i] = run
                return
        rows.append(run)

    async def get(self, sync_run_id: UUID, tenant_id: EntityId) -> SyncRun | None:
        for r in self._items.get(str(tenant_id), []):
            if r.sync_run_id == sync_run_id:
                return r
        return None

    async def find_running_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId
    ) -> SyncRun | None:
        for r in self._items.get(str(tenant_id), []):
            if r.connector_id.value == connector_id.value and r.status == SyncRunStatus.RUNNING:
                return r
        return None

    async def find_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId, limit: int = 20
    ) -> list[SyncRun]:
        rows = [
            r
            for r in self._items.get(str(tenant_id), [])
            if r.connector_id.value == connector_id.value
        ]
        rows.sort(key=lambda r: r.started_at, reverse=True)
        return rows[:limit]
