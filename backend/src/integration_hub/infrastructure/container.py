from __future__ import annotations

from typing import TYPE_CHECKING, Any

from integration_hub.application.services.asset_discovery_application_service import (
    AssetDiscoveryApplicationService,
)
from integration_hub.application.services.integration_hub_application_service import (
    IntegrationHubApplicationService,
)
from integration_hub.application.services.normalizer_registry import NormalizerRegistry
from integration_hub.domain.value_objects.enums import ConnectorType
from integration_hub.infrastructure.acl.credential_vault_adapter import CredentialVaultAdapter
from integration_hub.infrastructure.connectors.in_memory_action_connector import (
    InMemoryActionConnector,
)
from integration_hub.infrastructure.events.event_dispatcher import (
    EventDispatcher,
    log_event_handler,
)
from integration_hub.infrastructure.normalizers import register_all as register_all_normalizers
from integration_hub.infrastructure.observability.metrics_store import OperationalMetricsStore
from integration_hub.infrastructure.persistence.discovery_in_memory_repositories import (
    InMemoryDiscoveredAssetRepository,
    InMemorySyncRunRepository,
)
from integration_hub.infrastructure.persistence.in_memory_repositories import (
    InMemoryConnectorHealthRecordRepository,
    InMemoryConnectorRegistrationRepository,
)
from integration_hub.infrastructure.plugin_catalog import ConnectorPluginCatalog
from integration_hub.infrastructure.plugins import register_all as register_all_plugins
from integration_hub.infrastructure.vault.in_memory_vault import InMemoryCredentialVault
from integration_hub.infrastructure.workers.connector_health_worker import (
    ConnectorHealthWorker,
    HealthScheduler,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from integration_hub.domain.repositories.i_connector_repositories import (
        IConnectorHealthRecordRepository,
        IConnectorRegistrationRepository,
    )
    from integration_hub.domain.repositories.i_discovery_repositories import (
        IDiscoveredAssetRepository,
        ISyncRunRepository,
    )


class IntegrationHubContainer:
    registrations: IConnectorRegistrationRepository
    health_records: IConnectorHealthRecordRepository
    discovered_assets: IDiscoveredAssetRepository
    sync_runs: ISyncRunRepository

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        credential_service: Any | None = None,
    ) -> None:
        if session_factory is not None:
            from integration_hub.infrastructure.persistence.postgres_repositories import (
                PgConnectorHealthRecordRepository,
                PgConnectorRegistrationRepository,
                PgDiscoveredAssetRepository,
                PgSyncRunRepository,
            )

            self.registrations = PgConnectorRegistrationRepository(session_factory)
            self.health_records = PgConnectorHealthRecordRepository(session_factory)
            self.discovered_assets = PgDiscoveredAssetRepository(session_factory)
            self.sync_runs = PgSyncRunRepository(session_factory)
        else:
            self.registrations = InMemoryConnectorRegistrationRepository()
            self.health_records = InMemoryConnectorHealthRecordRepository()
            # In-memory discovery persistence is a test double only — used
            # whenever no session_factory is available (tests/dev without a
            # database), mirroring how registrations/health_records fall
            # back above.
            self.discovered_assets = InMemoryDiscoveredAssetRepository()
            self.sync_runs = InMemorySyncRunRepository()
        self.normalizers = NormalizerRegistry()
        register_all_normalizers(self.normalizers)
        # Legacy in-memory action connectors (ServiceNow/Jira/Slack/Teams —
        # ConnectorType enum members) — unaffected by the plugin catalog,
        # which handles credential-vault-backed connectors registered by
        # connector_id string (e.g. "openai") instead.
        self.vault = InMemoryCredentialVault()
        self.connectors = {t.value: InMemoryActionConnector() for t in ConnectorType}
        self.catalog = ConnectorPluginCatalog()
        register_all_plugins(self.catalog)
        # credential_service is the real credential_vault
        # CredentialApplicationService (see redforge/app.py's
        # _start_integration_hub_scheduler) — None only in tests/dev
        # without a database, where catalog-registered connectors fall
        # back to health_check reporting "adapter missing" rather than a
        # crash. Never falls back to os.environ or any other secret store.
        # Wrapped behind `ICredentialVaultPort` so application services
        # depend on integration_hub's own port, not on credential_vault's
        # concrete command types directly.
        self.credential_service = (
            CredentialVaultAdapter(credential_service) if credential_service is not None else None
        )
        # EventDispatcher is list-shaped (drop-in for the old plain list)
        # but also drains every event to registered handlers as it
        # arrives — see infrastructure/events/event_dispatcher.py. Logging
        # is the first real subscriber; more can `.subscribe(...)` later.
        self.event_sink = EventDispatcher()
        self.event_sink.subscribe(log_event_handler)
        self.metrics = OperationalMetricsStore()
        self.app = IntegrationHubApplicationService(
            self.registrations,
            self.health_records,
            self.connectors,
            self.event_sink,
            catalog=self.catalog,
            credential_service=self.credential_service,
        )
        self.health_worker = ConnectorHealthWorker(self.app)
        self.scheduler = HealthScheduler(self.health_worker)
        self.discovery = AssetDiscoveryApplicationService(
            self.discovered_assets,
            self.sync_runs,
            self.registrations,
            self.catalog,
            self.normalizers,
            self.event_sink,
            credential_service=self.credential_service,
            # Same CircuitBreakerService instance as health checks — one
            # breaker per connector registration, not a second mechanism.
            circuit=self.app.circuit,
        )
