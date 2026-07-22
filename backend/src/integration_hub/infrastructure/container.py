from __future__ import annotations

from typing import TYPE_CHECKING, Any

from integration_hub.application.services.integration_hub_application_service import (
    IntegrationHubApplicationService,
)
from integration_hub.domain.value_objects.enums import ConnectorType
from integration_hub.infrastructure.connectors.in_memory_action_connector import (
    InMemoryActionConnector,
)
from integration_hub.infrastructure.observability.metrics_store import OperationalMetricsStore
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


class IntegrationHubContainer:
    registrations: IConnectorRegistrationRepository
    health_records: IConnectorHealthRecordRepository

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        credential_service: Any | None = None,
    ) -> None:
        if session_factory is not None:
            from integration_hub.infrastructure.persistence.postgres_repositories import (
                PgConnectorHealthRecordRepository,
                PgConnectorRegistrationRepository,
            )

            self.registrations = PgConnectorRegistrationRepository(session_factory)
            self.health_records = PgConnectorHealthRecordRepository(session_factory)
        else:
            self.registrations = InMemoryConnectorRegistrationRepository()
            self.health_records = InMemoryConnectorHealthRecordRepository()
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
        self.credential_service = credential_service
        self.event_sink: list[object] = []
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
