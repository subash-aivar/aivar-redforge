from __future__ import annotations

from typing import TYPE_CHECKING

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
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
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
        # NOTE: credential vault stays in-memory here — this is a separate,
        # out-of-scope adapter (InMemoryCredentialVault), not the repository
        # this pass converts. ConnectorRegistration only ever stores a
        # CredentialRef (vault_key), never plaintext secrets; wiring this to
        # a real secret store is tracked separately from persistence work.
        self.vault = InMemoryCredentialVault()
        self.connectors = {t.value: InMemoryActionConnector() for t in ConnectorType}
        self.event_sink: list[object] = []
        self.metrics = OperationalMetricsStore()
        self.app = IntegrationHubApplicationService(
            self.registrations, self.health_records, self.connectors, self.event_sink
        )
        self.health_worker = ConnectorHealthWorker(self.app)
        self.scheduler = HealthScheduler(self.health_worker)
