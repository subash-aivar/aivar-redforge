from __future__ import annotations

from abc import ABC, abstractmethod

from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.value_objects.enums import ConnectorType
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class IConnectorRegistrationRepository(ABC):
    @abstractmethod
    async def save(self, registration: ConnectorRegistration, tenant_id: EntityId) -> None: ...

    @abstractmethod
    async def get(
        self, connector_id: ConnectorId, tenant_id: EntityId
    ) -> ConnectorRegistration | None: ...

    @abstractmethod
    async def find_healthy_for_action_type(
        self, tenant_id: EntityId, connector_type: ConnectorType
    ) -> list[ConnectorRegistration]: ...

    @abstractmethod
    async def find_all_for_tenant(self, tenant_id: EntityId) -> list[ConnectorRegistration]: ...


class IConnectorHealthRecordRepository(ABC):
    @abstractmethod
    async def append(self, record: ConnectorHealthRecord, tenant_id: EntityId) -> None: ...

    @abstractmethod
    async def find_latest_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId, limit: int
    ) -> list[ConnectorHealthRecord]: ...
