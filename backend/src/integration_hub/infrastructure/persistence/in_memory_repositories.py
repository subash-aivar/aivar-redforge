from __future__ import annotations

from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.repositories.i_connector_repositories import (
    IConnectorHealthRecordRepository,
    IConnectorRegistrationRepository,
)
from integration_hub.domain.value_objects.enums import ConnectorStatus, ConnectorType
from integration_hub.domain.value_objects.identifiers import ConnectorId, TenantId


class InMemoryConnectorRegistrationRepository(IConnectorRegistrationRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, ConnectorRegistration]] = {}

    async def save(self, registration: ConnectorRegistration, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(registration.connector_id)] = registration

    async def get(
        self, connector_id: ConnectorId, tenant_id: TenantId
    ) -> ConnectorRegistration | None:
        return self._items.get(str(tenant_id), {}).get(str(connector_id))

    async def find_healthy_for_action_type(
        self, tenant_id: TenantId, connector_type: ConnectorType
    ) -> list[ConnectorRegistration]:
        return [
            r
            for r in self._items.get(str(tenant_id), {}).values()
            if r.connector_type == connector_type
            and r.status in {ConnectorStatus.HEALTHY, ConnectorStatus.REGISTERED}
        ]

    async def find_all_for_tenant(self, tenant_id: TenantId) -> list[ConnectorRegistration]:
        return list(self._items.get(str(tenant_id), {}).values())


class InMemoryConnectorHealthRecordRepository(IConnectorHealthRecordRepository):
    def __init__(self) -> None:
        self._items: dict[str, list[ConnectorHealthRecord]] = {}

    async def append(self, record: ConnectorHealthRecord, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), []).append(record)

    async def find_latest_for_connector(
        self, connector_id: ConnectorId, tenant_id: TenantId, limit: int
    ) -> list[ConnectorHealthRecord]:
        rows = [
            r
            for r in self._items.get(str(tenant_id), [])
            if r.connector_id.value == connector_id.value
        ]
        rows.sort(key=lambda r: r.checked_at, reverse=True)
        return rows[:limit]
