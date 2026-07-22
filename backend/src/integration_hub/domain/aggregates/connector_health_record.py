from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from integration_hub.domain.value_objects.enums import ConnectorHealthStatus
from integration_hub.domain.value_objects.identifiers import (
    ConnectorHealthRecordId,
    ConnectorId,
    TenantId,
)


@dataclass
class ConnectorHealthRecord:
    record_id: ConnectorHealthRecordId
    tenant_id: TenantId
    connector_id: ConnectorId
    status: ConnectorHealthStatus
    response_time_ms: int | None
    error_detail: str | None
    checked_at: datetime

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        status: ConnectorHealthStatus,
        response_time_ms: int | None,
        error_detail: str | None,
        checked_at: datetime,
    ) -> ConnectorHealthRecord:
        return cls(
            ConnectorHealthRecordId.generate(),
            tenant_id,
            connector_id,
            status,
            response_time_ms,
            error_detail,
            checked_at,
        )
