"""DiscoveryService — runs discovery jobs through the connector pipeline.

Discovery Pipeline:
  Connector (ENABLED)
    → ConnectorProvider.discover() → DiscoveryResult (RawResource[])
    → InventoryMapperPort.map_batch() → DiscoveredAssetInput[]
    → InventoryService.run_pipeline_sync() → InventoryPipelineResult
    → DiscoverySnapshot

The DiscoveryService orchestrates this pipeline. It is stateless and
does NOT own the Connector lifecycle (that is ConnectorService's job).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.application.connectors.contracts import DiscoveryResult, DiscoverySnapshot
from redforge.application.connectors.registry import ConnectorRegistry
from redforge.application.inventory.contracts import DiscoveredAssetInput, InventoryContext
from redforge.application.inventory.inventory_service import InventoryService
from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.exceptions import ConnectorNotEnabledError

if TYPE_CHECKING:
    from redforge.application.connectors.contracts import CredentialProviderPort
    from redforge.application.inventory.inventory_service import InventoryPipelineResult

from ulid import ULID as _ULID


class DiscoveryService:
    """Orchestrates the discovery pipeline for a single connector run.

    Stateless. Accepts injected dependencies so it is fully testable
    without external infrastructure.
    """

    def __init__(
        self,
        registry: ConnectorRegistry,
        inventory_service: InventoryService | None = None,
        credential_provider: CredentialProviderPort | None = None,
    ) -> None:
        self._registry = registry
        self._inventory_service = inventory_service or InventoryService()
        self._credential_provider = credential_provider

    def run_discovery(
        self,
        connector: Connector,
        filters: dict[str, str] | None = None,
    ) -> tuple[DiscoveryResult, DiscoverySnapshot]:
        """Execute a full discovery pipeline for the given connector.

        1. Validate connector is ENABLED.
        2. Look up provider and mapper from registry.
        3. Call provider.discover() → DiscoveryResult (RawResources).
        4. Record job start on connector.
        5. Map resources → DiscoveredAssetInput via mapper.
        6. Feed into InventoryService pipeline.
        7. Record job completion on connector.
        8. Return (DiscoveryResult, DiscoverySnapshot).
        """
        if not connector.is_enabled:
            raise ConnectorNotEnabledError(str(connector.id), connector.status.value)

        provider = self._registry.get_provider(connector.connector_type)
        mapper = self._registry.get_mapper(connector.connector_type)

        job_id = str(_ULID())
        effective_filters = filters or {}

        connector.start_discovery_job(job_id, filters=tuple(effective_filters.items()))

        try:
            if provider is None:
                discovery_result = DiscoveryResult(
                    job_id=job_id,
                    connector_id=str(connector.id),
                    connector_type=connector.connector_type.value,
                    organization_id=str(connector.organization_id),
                    raw_resources=(),
                    error_message="No provider registered for this connector type",
                )
            else:
                credential = self._resolve_credential(connector)
                discovery_result = provider.discover(connector, credential, effective_filters)

            if discovery_result.error_message:
                connector.fail_discovery_job(job_id, discovery_result.error_message)
                snapshot = self._empty_snapshot(connector, job_id)
                return discovery_result, snapshot

            # Map raw resources → DiscoveredAssetInput
            inputs = self._map_resources(connector, discovery_result, mapper)

            # Feed into inventory pipeline
            org_id = str(connector.organization_id)
            ctx = InventoryContext(
                organization_id=org_id,
                discovered=inputs,
                period_label=datetime.now(UTC).isoformat()[:10],
            )
            pipeline_result = self._inventory_service.run_pipeline_sync(ctx)

            # Record completion
            connector.complete_discovery_job(
                job_id=job_id,
                assets_discovered=discovery_result.resource_count,
                assets_normalized=len(pipeline_result.all_assets),
                assets_failed=discovery_result.resource_count - len(inputs),
            )

            snapshot = self._build_snapshot(connector, job_id, discovery_result, pipeline_result)
            return discovery_result, snapshot

        except Exception as exc:
            error = str(exc)
            connector.fail_discovery_job(job_id, error)
            raise

    def run_batch_discovery(
        self,
        connectors: list[Connector],
        filters: dict[str, str] | None = None,
    ) -> list[tuple[Connector, DiscoveryResult, DiscoverySnapshot]]:
        """Run discovery on multiple connectors sequentially."""
        results = []
        for connector in connectors:
            try:
                disc_result, snap = self.run_discovery(connector, filters)
                results.append((connector, disc_result, snap))
            except Exception:
                # Individual failure does not stop the batch
                continue
        return results

    # ─── Private ──────────────────────────────────────────────────────────────

    def _resolve_credential(self, connector: Connector) -> str:
        if connector.credential_ref is None:
            return ""
        if self._credential_provider is None:
            return "stub-credential"
        return self._credential_provider.resolve(connector.credential_ref.reference_id)

    def _map_resources(
        self,
        connector: Connector,
        discovery_result: DiscoveryResult,
        mapper: object,
    ) -> tuple[DiscoveredAssetInput, ...]:
        from redforge.application.connectors.contracts import InventoryMapperPort
        if mapper is None or not isinstance(mapper, InventoryMapperPort):
            return ()
        return mapper.map_batch(
            discovery_result.raw_resources,
            str(connector.organization_id),
        )

    def _empty_snapshot(self, connector: Connector, job_id: str) -> DiscoverySnapshot:
        return DiscoverySnapshot(
            snapshot_id=str(_ULID()),
            connector_id=str(connector.id),
            connector_type=connector.connector_type.value,
            organization_id=str(connector.organization_id),
            total_resources_found=0,
            total_assets_mapped=0,
            total_assets_failed=0,
            created_at_iso=datetime.now(UTC).isoformat(),
        )

    def _build_snapshot(
        self,
        connector: Connector,
        job_id: str,
        discovery_result: DiscoveryResult,
        pipeline_result: InventoryPipelineResult,
    ) -> DiscoverySnapshot:
        type_counts: dict[str, int] = {}
        for asset in pipeline_result.all_assets:
            atype = asset.asset_type.value
            type_counts[atype] = type_counts.get(atype, 0) + 1

        return DiscoverySnapshot(
            snapshot_id=str(_ULID()),
            connector_id=str(connector.id),
            connector_type=connector.connector_type.value,
            organization_id=str(connector.organization_id),
            total_resources_found=discovery_result.resource_count,
            total_assets_mapped=len(pipeline_result.all_assets),
            total_assets_failed=(
                discovery_result.resource_count - len(pipeline_result.all_assets)
            ),
            asset_type_counts=type_counts,
            created_at_iso=datetime.now(UTC).isoformat(),
        )
