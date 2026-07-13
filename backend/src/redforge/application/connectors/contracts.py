"""Protocol contracts and DTOs for the Connector & Discovery framework.

All extension points are @runtime_checkable Protocols. No switch statements.
No provider-specific conditionals. Everything registry- or protocol-based.

Discovery Pipeline:
  Connector → DiscoveryProvider.discover() → RawResource[] →
  InventoryMapper.map() → DiscoveredAssetInput[] →
  InventoryService.run_pipeline() → InventorySnapshot
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.application.inventory.contracts import DiscoveredAssetInput
    from redforge.domain.connectors.entity import Connector
    from redforge.domain.connectors.value_objects import (
        ConnectorHealth,
        ConnectorType,
    )


# ─── DTOs ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RawResource:
    """A raw resource object returned by a connector's discovery operation.

    The connector returns these; the InventoryMapper converts them to
    DiscoveredAssetInput objects that the InventoryService understands.

    resource_type: platform-specific type string (e.g. "openai/model", "agent")
    external_id: stable identifier in the source system
    raw_data: arbitrary key-value payload from the source system
    """

    resource_type: str
    external_id: str
    name: str
    organization_id: str
    connector_type: str
    raw_data: dict[str, str] = field(default_factory=dict)
    related_resource_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiscoveryResult:
    """Result of a single discovery job execution.

    Wraps the raw resources returned by a connector before normalization.
    """

    job_id: str
    connector_id: str
    connector_type: str
    organization_id: str
    raw_resources: tuple[RawResource, ...]
    error_message: str = ""
    duration_seconds: float = 0.0

    @property
    def succeeded(self) -> bool:
        return not self.error_message

    @property
    def resource_count(self) -> int:
        return len(self.raw_resources)


@dataclass(frozen=True)
class DiscoverySnapshot:
    """Full snapshot of assets discovered from a single connector in one run.

    Produced after mapping raw resources to DiscoveredAssetInput objects.
    """

    snapshot_id: str
    connector_id: str
    connector_type: str
    organization_id: str
    total_resources_found: int
    total_assets_mapped: int
    total_assets_failed: int
    asset_type_counts: dict[str, int] = field(default_factory=dict)
    created_at_iso: str = ""

    @property
    def has_assets(self) -> bool:
        return self.total_assets_mapped > 0


@dataclass(frozen=True)
class SynchronizationResult:
    """Result of a completed synchronization job."""

    job_id: str
    connector_id: str
    assets_added: int
    assets_updated: int
    assets_unchanged: int
    assets_failed: int
    duration_seconds: float
    completed_at_iso: str
    is_full_sync: bool = False

    @property
    def total_processed(self) -> int:
        return self.assets_added + self.assets_updated + self.assets_unchanged

    @property
    def success_rate(self) -> float:
        total = self.total_processed + self.assets_failed
        if total == 0:
            return 1.0
        return (self.total_processed) / total


@dataclass(frozen=True)
class ConnectorRegistrationInput:
    """Input DTO for registering a new connector."""

    connector_type: str
    name: str
    description: str
    organization_id: str
    base_url: str = ""
    credential_reference_id: str = ""
    credential_type: str = "none"
    timeout_seconds: int = 30
    max_retries: int = 3
    page_size: int = 100
    custom_config: dict[str, str] = field(default_factory=dict)


# ─── Protocol Ports ───────────────────────────────────────────────────────────


@runtime_checkable
class ConnectorProvider(Protocol):
    """Provides connector plugin implementations.

    Each connector type has exactly one ConnectorProvider registered in
    the ConnectorRegistry. The provider knows how to discover resources
    and check health for its specific platform.
    """

    @property
    def connector_type(self) -> ConnectorType: ...

    def discover(
        self,
        connector: Connector,
        credential: str,
        filters: dict[str, str],
    ) -> DiscoveryResult: ...

    def check_health(
        self,
        connector: Connector,
        credential: str,
    ) -> ConnectorHealth: ...

    def validate_credential(
        self,
        connector: Connector,
        credential: str,
    ) -> bool: ...


@runtime_checkable
class InventoryMapperPort(Protocol):
    """Maps RawResource objects to DiscoveredAssetInput objects.

    One InventoryMapper per connector type, registered in the
    ConnectorRegistry alongside the ConnectorProvider.
    """

    @property
    def connector_type(self) -> ConnectorType: ...

    def map(
        self,
        resource: RawResource,
        organization_id: str,
    ) -> DiscoveredAssetInput | None: ...

    def map_batch(
        self,
        resources: tuple[RawResource, ...],
        organization_id: str,
    ) -> tuple[DiscoveredAssetInput, ...]: ...


@runtime_checkable
class CredentialProviderPort(Protocol):
    """Resolves credential secrets from an external vault or secret manager.

    Never returns None for a known reference — raises CredentialProviderError.
    """

    def resolve(self, reference_id: str) -> str: ...

    def exists(self, reference_id: str) -> bool: ...


@runtime_checkable
class ConnectorRepositoryPort(Protocol):
    """Persistence port for Connector aggregates."""

    async def save(self, connector: Connector) -> None: ...

    async def get_by_id(self, connector_id: str) -> Connector | None: ...

    async def get_by_type_and_org(
        self, connector_type: str, organization_id: str
    ) -> Connector | None: ...

    async def list_for_org(
        self,
        organization_id: str,
        status: str | None = None,
    ) -> list[Connector]: ...

    async def list_enabled(self) -> list[Connector]: ...

    async def delete(self, connector_id: str) -> None: ...


@runtime_checkable
class ConnectorSchedulerPort(Protocol):
    """Schedules periodic discovery and sync jobs for enabled connectors."""

    def schedule(self, connector_id: str, cron_expression: str) -> None: ...

    def unschedule(self, connector_id: str) -> None: ...

    def is_scheduled(self, connector_id: str) -> bool: ...

    def list_scheduled(self) -> list[str]: ...
