"""SyncService — orchestrates synchronization jobs for connectors.

Synchronization differs from discovery in that it is incremental:
it reconciles the current state of an external platform against what
RedForge already has in inventory, tracking adds / updates / unchanged.

SyncService is stateless. It delegates:
  - DiscoveryService.run_discovery()  → surface latest resources
  - ConnectorService.enable/disable() → lifecycle guard (caller's job)
  - Connector.start_sync_job() / complete_sync_job() / fail_sync_job()
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.application.connectors.contracts import SynchronizationResult
from redforge.application.connectors.discovery_service import DiscoveryService
from redforge.application.connectors.registry import ConnectorRegistry
from redforge.application.inventory.inventory_service import InventoryService
from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.exceptions import ConnectorNotEnabledError

if TYPE_CHECKING:
    from redforge.application.connectors.contracts import CredentialProviderPort

from ulid import ULID as _ULID


class SyncService:
    """Orchestrates periodic synchronization for ENABLED connectors.

    Each sync run:
      1. Guard: connector must be ENABLED.
      2. Run full discovery via DiscoveryService.
      3. Derive add/update/unchanged counts from pipeline result.
      4. Record job outcome on the Connector aggregate.
      5. Return SynchronizationResult.
    """

    def __init__(
        self,
        registry: ConnectorRegistry,
        inventory_service: InventoryService | None = None,
        credential_provider: CredentialProviderPort | None = None,
    ) -> None:
        self._discovery = DiscoveryService(
            registry=registry,
            inventory_service=inventory_service or InventoryService(),
            credential_provider=credential_provider,
        )

    def run_sync(
        self,
        connector: Connector,
        is_full_sync: bool = False,
        filters: dict[str, str] | None = None,
    ) -> SynchronizationResult:
        """Execute one synchronization cycle for the given connector.

        Returns a SynchronizationResult with per-category asset counts.
        """
        if not connector.is_enabled:
            raise ConnectorNotEnabledError(str(connector.id), connector.status.value)

        job_id = str(_ULID())
        started_at = datetime.now(UTC)

        connector.start_sync_job(job_id, is_full_sync=is_full_sync)

        try:
            _disc_result, snapshot = self._discovery.run_discovery(connector, filters)

            duration = (datetime.now(UTC) - started_at).total_seconds()

            # In a real implementation these counts would come from diffing
            # the incoming snapshot against the stored inventory.
            # Here we treat all mapped assets as additions (no prior state).
            assets_added = snapshot.total_assets_mapped
            assets_updated = 0
            assets_unchanged = 0
            assets_failed = snapshot.total_assets_failed

            connector.complete_sync_job(
                job_id=job_id,
                assets_added=assets_added,
                assets_updated=assets_updated,
                assets_unchanged=assets_unchanged,
            )

            return SynchronizationResult(
                job_id=job_id,
                connector_id=str(connector.id),
                assets_added=assets_added,
                assets_updated=assets_updated,
                assets_unchanged=assets_unchanged,
                assets_failed=assets_failed,
                duration_seconds=duration,
                completed_at_iso=datetime.now(UTC).isoformat(),
                is_full_sync=is_full_sync,
            )

        except Exception as exc:
            connector.fail_sync_job(job_id, str(exc))
            raise

    def run_batch_sync(
        self,
        connectors: list[Connector],
        is_full_sync: bool = False,
        filters: dict[str, str] | None = None,
    ) -> list[tuple[Connector, SynchronizationResult]]:
        """Run sync on multiple connectors sequentially; skip failures."""
        results = []
        for connector in connectors:
            try:
                result = self.run_sync(connector, is_full_sync=is_full_sync, filters=filters)
                results.append((connector, result))
            except Exception:
                continue
        return results
