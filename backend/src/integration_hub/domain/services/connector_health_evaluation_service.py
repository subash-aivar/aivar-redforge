from __future__ import annotations

from integration_hub.domain.value_objects.enums import ConnectorHealthStatus, ConnectorStatus


class ConnectorHealthEvaluationService:
    def to_connector_status(self, health: ConnectorHealthStatus) -> ConnectorStatus:
        return {
            ConnectorHealthStatus.HEALTHY: ConnectorStatus.HEALTHY,
            ConnectorHealthStatus.DEGRADED: ConnectorStatus.DEGRADED,
            ConnectorHealthStatus.UNHEALTHY: ConnectorStatus.UNHEALTHY,
        }[health]

    def evaluate_latency(self, response_time_ms: int | None) -> ConnectorHealthStatus:
        if response_time_ms is None:
            return ConnectorHealthStatus.UNHEALTHY
        if response_time_ms > 5000:
            return ConnectorHealthStatus.DEGRADED
        return ConnectorHealthStatus.HEALTHY
