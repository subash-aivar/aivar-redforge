from __future__ import annotations

from typing import Protocol
from uuid import UUID

from integration_hub.domain.aggregates.discovered_asset import DiscoveredAsset
from integration_hub.domain.aggregates.sync_run import SyncRun
from integration_hub.domain.value_objects.discovery import AssetRelationship
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class IDiscoveredAssetRepository(Protocol):
    async def save(self, asset: DiscoveredAsset, tenant_id: EntityId) -> None: ...

    async def get(self, asset_id: UUID, tenant_id: EntityId) -> DiscoveredAsset | None: ...

    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: EntityId
    ) -> DiscoveredAsset | None: ...

    async def get_by_fingerprints(
        self, fingerprints: list[str], tenant_id: EntityId
    ) -> dict[str, DiscoveredAsset]:
        """Bulk fingerprint lookup for a whole discovery page — one query
        instead of one `get_by_fingerprint` round trip per item, so the
        number of DB calls in `run_discovery` stays O(pages) rather than
        O(items)."""
        ...

    async def save_many(
        self, assets: list[DiscoveredAsset], tenant_id: EntityId
    ) -> None:
        """Persist a whole page of assets in a single session/commit
        instead of one commit per item."""
        ...

    async def find_all_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId
    ) -> list[DiscoveredAsset]: ...

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
    ) -> list[DiscoveredAsset]: ...

    async def find_relationships_for_assets(
        self, asset_ids: list[UUID], tenant_id: EntityId
    ) -> dict[UUID, list[AssetRelationship]]:
        """Batch-load relationships for a page of assets in a single query
        (`WHERE source_asset_id IN (...)`), keyed by source_asset_id —
        avoids the N+1 pattern of loading relationships once per asset."""
        ...

    async def delete(self, asset_id: UUID, tenant_id: EntityId) -> None: ...


class ISyncRunRepository(Protocol):
    async def save(self, run: SyncRun, tenant_id: EntityId) -> None: ...

    async def get(self, sync_run_id: UUID, tenant_id: EntityId) -> SyncRun | None: ...

    async def find_running_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId
    ) -> SyncRun | None:
        """Used by the concurrent-run guard: is there already a RUNNING
        sync run for this (tenant, connector)?"""
        ...

    async def find_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId, limit: int = 20
    ) -> list[SyncRun]: ...
