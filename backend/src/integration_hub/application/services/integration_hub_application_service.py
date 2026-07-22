from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from integration_hub.application._auth import require_admin
from integration_hub.application.commands.connector_commands import (
    DisableConnector,
    RegisterConnector,
    TriggerHealthCheck,
)
from integration_hub.application.dtos.connector_dtos import (
    ConnectorHealthDTO,
    ConnectorRegistrationDTO,
)
from integration_hub.application.exceptions import ApplicationNotFoundError
from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.events.connector_events import (
    ConnectorHealthCheckCompleted,
    ConnectorHealthDegraded,
    ConnectorHealthRestored,
)
from integration_hub.domain.services.circuit_breaker_service import CircuitBreakerService
from integration_hub.domain.services.connector_health_evaluation_service import (
    ConnectorHealthEvaluationService,
)
from integration_hub.domain.services.rate_limit_tracking_service import RateLimitTrackingService
from integration_hub.domain.value_objects.enums import (
    ConnectorHealthStatus,
    ConnectorStatus,
    ConnectorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, TenantId


class IntegrationHubApplicationService:
    def __init__(
        self,
        registrations: Any,
        health_records: Any,
        connectors: dict[str, Any],
        event_sink: list[Any] | None = None,
    ) -> None:
        self._regs = registrations
        self._health = health_records
        self._connectors = connectors
        self._events: list[Any] = event_sink if event_sink is not None else []
        self.circuit = CircuitBreakerService()
        self.health_eval = ConnectorHealthEvaluationService()
        self.rate_limits = RateLimitTrackingService()

    def _tenant(self, value: UUID) -> TenantId:
        return TenantId(value)

    def _dto(self, reg: ConnectorRegistration) -> ConnectorRegistrationDTO:
        return ConnectorRegistrationDTO(
            str(reg.connector_id),
            str(reg.tenant_id),
            reg.connector_type.value,
            reg.display_name,
            reg.status.value,
            reg.circuit_state.value,
            reg.credential_ref.vault_key,
            reg.credential_ref.credential_type,
        )

    async def register(self, cmd: RegisterConnector) -> ConnectorRegistrationDTO:
        require_admin(cmd.roles)
        tenant = self._tenant(cmd.tenant_id)
        reg = ConnectorRegistration.register(
            tenant,
            ConnectorType(cmd.connector_type),
            cmd.display_name,
            cmd.credential_vault_key,
            cmd.credential_type,
            base_url=cmd.base_url,
            configuration=cmd.configuration,
        )
        await self._regs.save(reg, tenant)
        self._events.extend(reg.pop_events())
        return self._dto(reg)

    async def disable(self, cmd: DisableConnector) -> ConnectorRegistrationDTO:
        require_admin(cmd.roles)
        tenant = self._tenant(cmd.tenant_id)
        reg = await self._regs.get(ConnectorId(cmd.connector_id), tenant)
        if reg is None:
            raise ApplicationNotFoundError("connector not found")
        reg.disable(tenant, cmd.disabled_by, cmd.reason)
        await self._regs.save(reg, tenant)
        self._events.extend(reg.pop_events())
        return self._dto(reg)

    async def health_check(self, cmd: TriggerHealthCheck) -> ConnectorHealthDTO:
        tenant = self._tenant(cmd.tenant_id)
        reg = await self._regs.get(ConnectorId(cmd.connector_id), tenant)
        if reg is None:
            raise ApplicationNotFoundError("connector not found")
        self.circuit.maybe_half_open(reg)
        adapter = self._connectors.get(reg.connector_type.value)
        now = datetime.now(UTC)
        if adapter is None:
            status = ConnectorHealthStatus.UNHEALTHY
            latency = None
            detail = "adapter missing"
        else:
            try:
                status = await adapter.health_check(str(tenant))
                latency = 10
                detail = None
            except Exception as exc:
                status = ConnectorHealthStatus.UNHEALTHY
                latency = None
                detail = str(exc)
        prev = reg.status
        mapped = self.health_eval.to_connector_status(status)
        if reg.status != ConnectorStatus.DISABLED:
            reg.apply_health(mapped, now)
        record = ConnectorHealthRecord.create(
            tenant, reg.connector_id, status, latency, detail, now
        )
        await self._health.append(record, tenant)
        if status == ConnectorHealthStatus.HEALTHY:
            self.circuit.record_success(reg)
            if prev in {ConnectorStatus.DEGRADED, ConnectorStatus.UNHEALTHY}:
                self._events.append(
                    ConnectorHealthRestored(
                        tenant_id=str(tenant),
                        aggregate_id=str(reg.connector_id),
                        connector_id=str(reg.connector_id),
                        restored_at=now.isoformat(),
                    )
                )
        else:
            self.circuit.record_failure(reg, at=now)
            self._events.append(
                ConnectorHealthDegraded(
                    tenant_id=str(tenant),
                    aggregate_id=str(reg.connector_id),
                    connector_id=str(reg.connector_id),
                    from_status=prev.value,
                    to_status=mapped.value,
                    error_detail=detail,
                    degraded_at=now.isoformat(),
                )
            )
        await self._regs.save(reg, tenant)
        self._events.append(
            ConnectorHealthCheckCompleted(
                tenant_id=str(tenant),
                aggregate_id=str(reg.connector_id),
                connector_id=str(reg.connector_id),
                status=status.value,
                response_time_ms=latency,
                checked_at=now.isoformat(),
            )
        )
        return ConnectorHealthDTO(
            str(reg.connector_id),
            status.value,
            latency,
            now.isoformat(),
            reg.circuit_state.value,
        )

    async def list_connectors(
        self, tenant_id: UUID, roles: tuple[str, ...], status_filter: str | None = None
    ) -> list[ConnectorRegistrationDTO]:
        require_admin(roles)
        rows = await self._regs.find_all_for_tenant(self._tenant(tenant_id))
        if status_filter:
            rows = [r for r in rows if r.status.value == status_filter]
        return [self._dto(r) for r in rows]

    async def get_connector(
        self, tenant_id: UUID, connector_id: UUID, roles: tuple[str, ...]
    ) -> ConnectorRegistrationDTO:
        if "integration:admin" not in roles and "playbook:analyst" not in roles:
            require_admin(roles)
        reg = await self._regs.get(ConnectorId(connector_id), self._tenant(tenant_id))
        if reg is None:
            raise ApplicationNotFoundError("connector not found")
        return self._dto(reg)

    async def health_history(
        self, tenant_id: UUID, connector_id: UUID, roles: tuple[str, ...], limit: int = 20
    ) -> list[dict[str, object]]:
        if "integration:admin" not in roles and "playbook:analyst" not in roles:
            require_admin(roles)
        rows = await self._health.find_latest_for_connector(
            ConnectorId(connector_id), self._tenant(tenant_id), limit
        )
        return [
            {
                "status": r.status.value,
                "response_time_ms": r.response_time_ms,
                "checked_at": r.checked_at.isoformat(),
                "error_detail": r.error_detail,
            }
            for r in rows
        ]
