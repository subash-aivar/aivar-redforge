"""ConnectorRegistration aggregate — CredentialRef only, no plaintext secrets."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from integration_hub.domain.events.connector_events import ConnectorDisabled, ConnectorRegistered
from integration_hub.domain.exceptions.domain_exceptions import (
    ConnectorDisabledError,
    DomainInvariantViolation,
    TenantMismatch,
)
from integration_hub.domain.value_objects.credentials import CredentialRef
from integration_hub.domain.value_objects.enums import (
    CircuitState,
    ConnectorStatus,
    ConnectorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class ConnectorRegistration:
    __slots__ = (
        "_pending_events",
        "base_url",
        "circuit_failure_count",
        "circuit_opened_at",
        "circuit_state",
        "configuration",
        "connector_id",
        "connector_type",
        "created_at",
        "credential_ref",
        "display_name",
        "last_health_check_at",
        "status",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        connector_id: ConnectorId,
        tenant_id: EntityId,
        connector_type: ConnectorType | str,
        display_name: str,
        status: ConnectorStatus,
        credential_ref: CredentialRef,
        *,
        base_url: str | None = None,
        configuration: dict[str, object] | None = None,
        created_at: datetime | None = None,
        last_health_check_at: datetime | None = None,
        circuit_state: CircuitState = CircuitState.CLOSED,
        circuit_failure_count: int = 0,
        circuit_opened_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        self.connector_id = connector_id
        self.tenant_id = tenant_id
        self.connector_type = connector_type
        self.display_name = display_name
        self.status = status
        self.credential_ref = credential_ref
        self.base_url = base_url
        self.configuration = dict(configuration or {})
        self.created_at = created_at or datetime.now(UTC)
        self.last_health_check_at = last_health_check_at
        self.circuit_state = circuit_state
        self.circuit_failure_count = circuit_failure_count
        self.circuit_opened_at = circuit_opened_at
        self.updated_at = updated_at or self.created_at
        self._pending_events: list[Any] = []
        banned = {
            "api_key",
            "secret",
            "password",
            "token",
            "private_key",
            "certificate",
            "credential",
        }
        if banned.intersection(self.configuration):
            raise DomainInvariantViolation("configuration must not contain secret fields")

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _assert_tenant(self, tenant_id: EntityId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    @classmethod
    def register(
        cls,
        tenant_id: EntityId,
        connector_type: ConnectorType | str,
        display_name: str,
        credential_vault_key: str,
        credential_type: str,
        *,
        base_url: str | None = None,
        configuration: dict[str, object] | None = None,
    ) -> ConnectorRegistration:
        now = datetime.now(UTC)
        reg = cls(
            ConnectorId.generate(),
            tenant_id,
            connector_type,
            display_name,
            ConnectorStatus.REGISTERED,
            CredentialRef(credential_vault_key, str(tenant_id), credential_type),
            base_url=base_url,
            configuration=configuration,
            created_at=now,
        )
        reg._pending_events.append(
            ConnectorRegistered(
                tenant_id=str(tenant_id),
                aggregate_id=str(reg.connector_id),
                connector_id=str(reg.connector_id),
                connector_type=str(connector_type),
                display_name=display_name,
                registered_at=now.isoformat(),
            )
        )
        return reg

    def disable(self, tenant_id: EntityId, disabled_by: str, reason: str) -> None:
        self._assert_tenant(tenant_id)
        now = datetime.now(UTC)
        self.status = ConnectorStatus.DISABLED
        self.updated_at = now
        self._pending_events.append(
            ConnectorDisabled(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.connector_id),
                connector_id=str(self.connector_id),
                disabled_by=disabled_by,
                reason=reason,
                disabled_at=now.isoformat(),
            )
        )

    def assert_executable(self) -> None:
        if self.status == ConnectorStatus.DISABLED:
            raise ConnectorDisabledError("connector disabled")
        if self.circuit_state == CircuitState.OPEN:
            from integration_hub.domain.exceptions.domain_exceptions import CircuitOpenError

            raise CircuitOpenError("circuit open")

    def apply_circuit(
        self, state: CircuitState, failure_count: int, opened_at: datetime | None
    ) -> None:
        self.circuit_state = state
        self.circuit_failure_count = failure_count
        self.circuit_opened_at = opened_at
        self.updated_at = datetime.now(UTC)

    def apply_health(self, status: ConnectorStatus, checked_at: datetime) -> None:
        self.status = status
        self.last_health_check_at = checked_at
        self.updated_at = checked_at
