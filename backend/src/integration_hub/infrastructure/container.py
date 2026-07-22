from __future__ import annotations

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


class IntegrationHubContainer:
    def __init__(self) -> None:
        self.registrations = InMemoryConnectorRegistrationRepository()
        self.health_records = InMemoryConnectorHealthRecordRepository()
        self.vault = InMemoryCredentialVault()
        self.connectors = {t.value: InMemoryActionConnector() for t in ConnectorType}
        self.event_sink: list[object] = []
        self.metrics = OperationalMetricsStore()
        self.app = IntegrationHubApplicationService(
            self.registrations, self.health_records, self.connectors, self.event_sink
        )
        self.health_worker = ConnectorHealthWorker(self.app)
        self.scheduler = HealthScheduler(self.health_worker)
