from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from integration_hub.application._auth import require_admin
from integration_hub.application.commands.connector_commands import (
    DisableConnector,
    RegisterConnector,
    RegisterConnectorWithCredential,
    TriggerHealthCheck,
)
from integration_hub.application.dtos.connector_dtos import (
    ConnectorHealthDTO,
    ConnectorRegistrationDTO,
)
from integration_hub.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from integration_hub.application.ports.credential_vault import ICredentialVaultPort
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
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId, TenantId
from integration_hub.infrastructure.plugin_catalog import ConnectorPluginCatalog


class IntegrationHubApplicationService:
    def __init__(
        self,
        registrations: Any,
        health_records: Any,
        connectors: dict[str, Any],
        event_sink: list[Any] | None = None,
        catalog: ConnectorPluginCatalog | None = None,
        credential_service: ICredentialVaultPort | None = None,
    ) -> None:
        self._regs = registrations
        self._health = health_records
        self._connectors = connectors
        self._events: list[Any] = event_sink if event_sink is not None else []
        self.circuit = CircuitBreakerService()
        self.health_eval = ConnectorHealthEvaluationService()
        self.rate_limits = RateLimitTrackingService()
        self._catalog = catalog
        self._credential_service = credential_service

    def _tenant(self, value: TenantId | UUID) -> EntityId:
        """Normalize either an already-canonical `TenantId` (=`EntityId`) or
        a raw `uuid.UUID` into one consistent `EntityId` — see the
        identical fix/rationale in
        `AssetDiscoveryApplicationService._tenant`. Previously
        `EntityId(value)` either double-wrapped an already-good `EntityId`
        (breaking `==`/hashing) or built a `ULID`-typed slot holding a
        plain `UUID`, incompatible with a canonically-built `EntityId` for
        the same value."""
        if isinstance(value, EntityId):
            return value
        return EntityId.from_uuid(value)

    def _dto(self, reg: ConnectorRegistration) -> ConnectorRegistrationDTO:
        return ConnectorRegistrationDTO(
            str(reg.connector_id),
            str(reg.tenant_id),
            str(reg.connector_type),
            reg.display_name,
            reg.status.value,
            reg.circuit_state.value,
            reg.credential_ref.vault_key,
            reg.credential_ref.credential_type,
        )

    def list_catalog(self) -> list[Any]:
        """Available connector plugins for the setup wizard. Empty list if
        no catalog was wired (e.g. legacy in-memory test container)."""
        return self._catalog.list_all() if self._catalog else []

    async def register(self, cmd: RegisterConnector) -> ConnectorRegistrationDTO:
        require_admin(cmd.roles)
        tenant = self._tenant(cmd.tenant_id)
        known_legacy = cmd.connector_type in {t.value for t in ConnectorType}
        known_plugin = bool(self._catalog and self._catalog.has_type(cmd.connector_type))
        if not known_legacy and not known_plugin:
            raise ApplicationValidationError(f"unknown connector_type: {cmd.connector_type}")
        reg = ConnectorRegistration.register(
            tenant,
            cmd.connector_type,
            cmd.display_name,
            cmd.credential_vault_key,
            cmd.credential_type,
            base_url=cmd.base_url,
            configuration=cmd.configuration,
        )
        await self._regs.save(reg, tenant)
        self._events.extend(reg.pop_events())
        return self._dto(reg)

    async def register_with_credential(
        self, cmd: RegisterConnectorWithCredential
    ) -> ConnectorRegistrationDTO:
        """Self-service registration through the setup wizard: creates the
        secret in credential_vault (never inline), then registers the
        connector holding only the resulting vault pointer."""
        require_admin(cmd.roles)
        if self._credential_service is None:
            raise ApplicationValidationError(
                "credential vault is not wired — cannot register a credentialed connector"
            )
        plugin = self._catalog.get(cmd.connector_id) if self._catalog else None
        if plugin is None:
            raise ApplicationValidationError(f"unknown connector_id: {cmd.connector_id}")

        tenant = self._tenant(cmd.tenant_id)
        primary_field = plugin.credential_fields[0]
        credential_id = await self._credential_service.create(
            tenant_id=cmd.tenant_id,
            name=f"integration.{plugin.connector_id}.{cmd.display_name}",
            category=primary_field.vault_category,
            subtype=primary_field.vault_subtype,
            owner_principal_id=cmd.owner_principal_id,
            vault_backend_id=cmd.vault_backend_id,
            plaintext_secret=cmd.plaintext_secret.encode("utf-8"),
            description=f"Integration Hub connector: {plugin.display_name}",
            tags={"connector_type": plugin.connector_id, "integration_hub": "true"},
        )

        # Immediate connectivity test with the plaintext secret we already
        # hold in this request — no need to round-trip through the vault
        # again just to validate the credential the admin just supplied.
        config = {k: str(v) for k, v in (cmd.configuration or {}).items()}
        test_status = await plugin.health_check(cmd.plaintext_secret, config)

        reg = ConnectorRegistration.register(
            tenant,
            plugin.connector_id,
            cmd.display_name,
            credential_id,
            primary_field.vault_category,
            base_url=None,
            configuration=cmd.configuration,
        )
        now = datetime.now(UTC)
        mapped = self.health_eval.to_connector_status(test_status)
        reg.apply_health(mapped, now)
        await self._regs.save(reg, tenant)
        self._events.extend(reg.pop_events())
        await self._health.append(
            ConnectorHealthRecord.create(tenant, reg.connector_id, test_status, None, None, now),
            tenant,
        )
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
        now = datetime.now(UTC)
        plugin = self._catalog.get(str(reg.connector_type)) if self._catalog else None
        if plugin is not None and self._credential_service is not None:
            try:
                resolved = await self._credential_service.resolve(
                    tenant_id=cmd.tenant_id,
                    credential_id=UUID(reg.credential_ref.vault_key),
                    principal_id=cmd.tenant_id,  # system-triggered health check
                    purpose="integration_hub.health_check",
                )
                secret = resolved.secret_value
                config = {k: str(v) for k, v in (reg.configuration or {}).items()}
                status = await plugin.health_check(secret, config)
                latency = 10
                detail = None
            except Exception as exc:
                status = ConnectorHealthStatus.UNHEALTHY
                latency = None
                detail = str(exc)
        else:
            adapter = self._connectors.get(str(reg.connector_type))
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
        self, tenant_id: TenantId, roles: tuple[str, ...], status_filter: str | None = None
    ) -> list[ConnectorRegistrationDTO]:
        require_admin(roles)
        rows = await self._regs.find_all_for_tenant(self._tenant(tenant_id))
        if status_filter:
            rows = [r for r in rows if r.status.value == status_filter]
        return [self._dto(r) for r in rows]

    async def get_connector(
        self, tenant_id: TenantId, connector_id: UUID, roles: tuple[str, ...]
    ) -> ConnectorRegistrationDTO:
        if "integration:admin" not in roles and "playbook:analyst" not in roles:
            require_admin(roles)
        reg = await self._regs.get(ConnectorId(connector_id), self._tenant(tenant_id))
        if reg is None:
            raise ApplicationNotFoundError("connector not found")
        return self._dto(reg)

    async def health_history(
        self, tenant_id: TenantId, connector_id: UUID, roles: tuple[str, ...], limit: int = 20
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
