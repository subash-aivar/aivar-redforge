from __future__ import annotations

from dataclasses import dataclass

from integration_hub.domain.events.base import BaseConnectorEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorRegistered(BaseConnectorEvent):
    connector_id: str
    connector_type: str
    display_name: str
    registered_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorHealthCheckCompleted(BaseConnectorEvent):
    connector_id: str
    status: str
    response_time_ms: int | None
    checked_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorHealthDegraded(BaseConnectorEvent):
    connector_id: str
    from_status: str
    to_status: str
    error_detail: str | None
    degraded_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorHealthRestored(BaseConnectorEvent):
    connector_id: str
    restored_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorDisabled(BaseConnectorEvent):
    connector_id: str
    disabled_by: str
    reason: str
    disabled_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorUnavailable(BaseConnectorEvent):
    connector_id: str
    reason: str
    recorded_at: str
