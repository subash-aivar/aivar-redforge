"""Generate integration_hub bounded context."""

from __future__ import annotations

from .common import CONNECTOR_TYPES, FAILURE_MODES, SRC, TESTS, empty_inits, w


def write() -> None:
    base = SRC / "integration_hub"
    empty_inits(
        base,
        base / "domain",
        base / "domain" / "aggregates",
        base / "domain" / "events",
        base / "domain" / "exceptions",
        base / "domain" / "repositories",
        base / "domain" / "services",
        base / "domain" / "value_objects",
        base / "application",
        base / "application" / "commands",
        base / "application" / "dtos",
        base / "application" / "services",
        base / "application" / "ports",
        base / "infrastructure",
        base / "infrastructure" / "persistence",
        base / "infrastructure" / "workers",
        base / "infrastructure" / "connectors",
        base / "infrastructure" / "vault",
        base / "infrastructure" / "observability",
        base / "api",
        base / "api" / "v1",
    )
    w(base / "__init__.py", '"""M35 integration_hub bounded context."""\n')
    w(base / "py.typed", "")
    _domain(base)
    _app(base)
    _infra(base)
    _api(base)
    _tests()


def _domain(base):
    w(
        base / "domain" / "value_objects" / "enums.py",
        f'''"""Frozen enums for integration_hub BC (M35)."""

from __future__ import annotations

from enum import StrEnum

{CONNECTOR_TYPES}

class ConnectorStatus(StrEnum):
    REGISTERED = "REGISTERED"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    DISABLED = "DISABLED"


class ConnectorHealthStatus(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

{FAILURE_MODES}
''',
    )
    w(
        base / "domain" / "value_objects" / "identifiers.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ConnectorId:
    value: UUID

    @classmethod
    def generate(cls) -> ConnectorId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ConnectorHealthRecordId:
    value: UUID

    @classmethod
    def generate(cls) -> ConnectorHealthRecordId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
''',
    )
    w(
        base / "domain" / "value_objects" / "credentials.py",
        '''"""CredentialRef / ResolvedCredential — ADR-M35-003."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class CredentialRef:
    vault_key: str
    tenant_id: str
    credential_type: str


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    credential_type: str
    secret_value: str
    expires_at: datetime | None
''',
    )
    w(
        base / "domain" / "value_objects" / "results.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from integration_hub.domain.value_objects.enums import ConnectorFailureMode


@dataclass(frozen=True, slots=True)
class ConnectorActionResult:
    success: bool
    failure_mode: ConnectorFailureMode | None
    external_reference: str | None
    response_payload: dict[str, object]
    executed_at: datetime
    duration_ms: int
    rollback_available: bool
    rollback_parameters: dict[str, object]
''',
    )
    w(
        base / "domain" / "exceptions" / "domain_exceptions.py",
        '''from __future__ import annotations


class IntegrationHubDomainError(Exception):
    pass


class DomainInvariantViolation(IntegrationHubDomainError):
    pass


class TenantMismatch(IntegrationHubDomainError):
    pass


class CircuitOpenError(IntegrationHubDomainError):
    pass


class ConnectorDisabledError(IntegrationHubDomainError):
    pass
''',
    )
    w(
        base / "domain" / "events" / "base.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseConnectorEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""
''',
    )
    w(
        base / "domain" / "events" / "connector_events.py",
        '''from __future__ import annotations

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
''',
    )
    w(
        base / "domain" / "aggregates" / "connector_registration.py",
        '''"""ConnectorRegistration aggregate — CredentialRef only, no plaintext secrets."""

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
from integration_hub.domain.value_objects.identifiers import ConnectorId, TenantId


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
        tenant_id: TenantId,
        connector_type: ConnectorType,
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
        banned = {"api_key", "secret", "password", "token", "private_key", "certificate", "credential"}
        if banned.intersection(self.configuration):
            raise DomainInvariantViolation("configuration must not contain secret fields")

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    @classmethod
    def register(
        cls,
        tenant_id: TenantId,
        connector_type: ConnectorType,
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
                connector_type=connector_type.value,
                display_name=display_name,
                registered_at=now.isoformat(),
            )
        )
        return reg

    def disable(self, tenant_id: TenantId, disabled_by: str, reason: str) -> None:
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
''',
    )
    w(
        base / "domain" / "aggregates" / "connector_health_record.py",
        '''from __future__ import annotations

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
''',
    )
    w(
        base / "domain" / "services" / "circuit_breaker_service.py",
        '''"""Circuit breaker — ADR-M35-006."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.value_objects.enums import CircuitState


class CircuitBreakerService:
    FAILURE_THRESHOLD = 5
    WINDOW = timedelta(minutes=2)
    OPEN_DURATION = timedelta(seconds=30)

    def __init__(self) -> None:
        self._failure_times: dict[str, list[datetime]] = {}

    def record_success(self, registration: ConnectorRegistration) -> None:
        key = str(registration.connector_id)
        self._failure_times[key] = []
        registration.apply_circuit(CircuitState.CLOSED, 0, None)

    def record_failure(self, registration: ConnectorRegistration, *, at: datetime | None = None) -> None:
        now = at or datetime.now(UTC)
        key = str(registration.connector_id)
        times = [t for t in self._failure_times.get(key, []) if now - t <= self.WINDOW]
        times.append(now)
        self._failure_times[key] = times
        if registration.circuit_state == CircuitState.HALF_OPEN:
            registration.apply_circuit(CircuitState.OPEN, len(times), now)
            return
        if len(times) >= self.FAILURE_THRESHOLD:
            registration.apply_circuit(CircuitState.OPEN, len(times), now)
        else:
            registration.apply_circuit(CircuitState.CLOSED, len(times), None)

    def maybe_half_open(self, registration: ConnectorRegistration, *, at: datetime | None = None) -> None:
        now = at or datetime.now(UTC)
        if registration.circuit_state != CircuitState.OPEN:
            return
        if registration.circuit_opened_at and now - registration.circuit_opened_at >= self.OPEN_DURATION:
            registration.apply_circuit(
                CircuitState.HALF_OPEN, registration.circuit_failure_count, registration.circuit_opened_at
            )

    def allow_request(self, registration: ConnectorRegistration, *, at: datetime | None = None) -> bool:
        self.maybe_half_open(registration, at=at)
        return registration.circuit_state != CircuitState.OPEN
''',
    )
    w(
        base / "domain" / "services" / "connector_health_evaluation_service.py",
        '''from __future__ import annotations

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
''',
    )
    w(
        base / "domain" / "services" / "rate_limit_tracking_service.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass
class RateWindow:
    window_start: datetime
    action_count: int = 0
    budget: int = 100


@dataclass
class RateLimitTrackingService:
    windows: dict[str, RateWindow] = field(default_factory=dict)
    window_size: timedelta = timedelta(hours=1)

    def consume(self, connector_id: str, *, cost: int = 1) -> int:
        now = datetime.now(UTC)
        win = self.windows.get(connector_id)
        if win is None or now - win.window_start >= self.window_size:
            win = RateWindow(now)
            self.windows[connector_id] = win
        win.action_count += cost
        remaining = max(0, win.budget - win.action_count)
        return remaining

    def budget_remaining(self, connector_id: str) -> int:
        win = self.windows.get(connector_id)
        if win is None:
            return 100
        return max(0, win.budget - win.action_count)
''',
    )
    w(
        base / "domain" / "services" / "credential_resolution_service.py",
        '''from __future__ import annotations

from typing import Protocol

from integration_hub.domain.value_objects.credentials import CredentialRef, ResolvedCredential


class CredentialVaultPort(Protocol):
    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential: ...


class CredentialResolutionService:
    def __init__(self, vault: CredentialVaultPort) -> None:
        self._vault = vault

    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential:
        if ref.tenant_id != tenant_id:
            raise ValueError("credential tenant mismatch")
        return await self._vault.resolve(ref, tenant_id)
''',
    )
    w(
        base / "domain" / "repositories" / "i_connector_repositories.py",
        '''from __future__ import annotations

from abc import ABC, abstractmethod

from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.value_objects.enums import ConnectorType
from integration_hub.domain.value_objects.identifiers import ConnectorId, TenantId


class IConnectorRegistrationRepository(ABC):
    @abstractmethod
    async def save(self, registration: ConnectorRegistration, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def get(
        self, connector_id: ConnectorId, tenant_id: TenantId
    ) -> ConnectorRegistration | None: ...

    @abstractmethod
    async def find_healthy_for_action_type(
        self, tenant_id: TenantId, connector_type: ConnectorType
    ) -> list[ConnectorRegistration]: ...

    @abstractmethod
    async def find_all_for_tenant(self, tenant_id: TenantId) -> list[ConnectorRegistration]: ...


class IConnectorHealthRecordRepository(ABC):
    @abstractmethod
    async def append(self, record: ConnectorHealthRecord, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_latest_for_connector(
        self, connector_id: ConnectorId, tenant_id: TenantId, limit: int
    ) -> list[ConnectorHealthRecord]: ...
''',
    )


def _app(base):
    w(
        base / "application" / "exceptions.py",
        '''from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationNotFoundError(ApplicationError):
    pass


class ApplicationForbiddenError(ApplicationError):
    pass
''',
    )
    w(
        base / "application" / "_auth.py",
        '''from __future__ import annotations

from integration_hub.application.exceptions import ApplicationForbiddenError


def require_admin(roles: tuple[str, ...]) -> None:
    if "integration:admin" not in roles and "incident:ciso" not in roles:
        raise ApplicationForbiddenError("integration:admin")
''',
    )
    w(
        base / "application" / "ports" / "action_connector.py",
        '''from __future__ import annotations

from typing import Protocol

from integration_hub.domain.value_objects.enums import ConnectorHealthStatus
from integration_hub.domain.value_objects.results import ConnectorActionResult


class IActionConnector(Protocol):
    async def execute(
        self, action_type: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult: ...

    async def rollback(
        self, original_action_id: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult: ...

    async def health_check(self, tenant_id: str) -> ConnectorHealthStatus: ...

    async def verify_outcome(
        self, execution_id: str, step_number: int, tenant_id: str
    ) -> ConnectorActionResult | None: ...
''',
    )
    w(
        base / "application" / "ports" / "credential_vault.py",
        '''from __future__ import annotations

from typing import Protocol

from integration_hub.domain.value_objects.credentials import CredentialRef, ResolvedCredential


class ICredentialVaultPort(Protocol):
    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential: ...
''',
    )
    w(
        base / "application" / "commands" / "connector_commands.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RegisterConnector:
    tenant_id: UUID
    connector_type: str
    display_name: str
    credential_vault_key: str
    credential_type: str
    registered_by: str
    roles: tuple[str, ...]
    configuration: dict[str, object] | None = None
    base_url: str | None = None


@dataclass(frozen=True, slots=True)
class DisableConnector:
    tenant_id: UUID
    connector_id: UUID
    disabled_by: str
    reason: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TriggerHealthCheck:
    tenant_id: UUID
    connector_id: UUID
    roles: tuple[str, ...]
''',
    )
    w(
        base / "application" / "dtos" / "connector_dtos.py",
        '''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConnectorRegistrationDTO:
    connector_id: str
    tenant_id: str
    connector_type: str
    display_name: str
    status: str
    circuit_state: str
    credential_vault_key: str
    credential_type: str


@dataclass(frozen=True, slots=True)
class ConnectorHealthDTO:
    connector_id: str
    status: str
    response_time_ms: int | None
    checked_at: str | None
    circuit_state: str
''',
    )
    w(
        base / "application" / "services" / "integration_hub_application_service.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from integration_hub.application._auth import require_admin
from integration_hub.application.commands.connector_commands import (
    DisableConnector,
    RegisterConnector,
    TriggerHealthCheck,
)
from integration_hub.application.dtos.connector_dtos import ConnectorHealthDTO, ConnectorRegistrationDTO
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
            except Exception as exc:  # noqa: BLE001
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
''',
    )


def _infra(base):
    w(
        base / "infrastructure" / "persistence" / "in_memory_repositories.py",
        '''from __future__ import annotations

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
''',
    )
    w(
        base / "infrastructure" / "vault" / "in_memory_vault.py",
        '''from __future__ import annotations

from datetime import UTC, datetime, timedelta

from integration_hub.domain.value_objects.credentials import CredentialRef, ResolvedCredential


class InMemoryCredentialVault:
    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._cache: dict[str, tuple[ResolvedCredential, datetime]] = {}
        self.ttl = timedelta(minutes=5)

    def put(self, vault_key: str, secret_value: str) -> None:
        self._secrets[vault_key] = secret_value

    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential:
        if ref.tenant_id != tenant_id:
            raise ValueError("tenant mismatch")
        now = datetime.now(UTC)
        cached = self._cache.get(ref.vault_key)
        if cached and now - cached[1] < self.ttl:
            return cached[0]
        secret = self._secrets.get(ref.vault_key, f"resolved:{ref.vault_key}")
        resolved = ResolvedCredential(ref.credential_type, secret, now + timedelta(minutes=10))
        self._cache[ref.vault_key] = (resolved, now)
        return resolved
''',
    )
    w(
        base / "infrastructure" / "connectors" / "in_memory_action_connector.py",
        '''from __future__ import annotations

from datetime import UTC, datetime

from integration_hub.domain.value_objects.enums import ConnectorFailureMode, ConnectorHealthStatus
from integration_hub.domain.value_objects.results import ConnectorActionResult


class InMemoryActionConnector:
    def __init__(self, *, fail_mode: ConnectorFailureMode | None = None) -> None:
        self.fail_mode = fail_mode
        self.executions: list[dict[str, object]] = []
        self.verify_results: dict[str, ConnectorActionResult] = {}

    async def execute(
        self, action_type: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult:
        now = datetime.now(UTC)
        self.executions.append(
            {"action_type": action_type, "parameters": parameters, "tenant_id": tenant_id}
        )
        if self.fail_mode is not None:
            return ConnectorActionResult(
                False,
                self.fail_mode,
                None,
                {"error": self.fail_mode.value},
                now,
                5,
                False,
                {},
            )
        ref = f"ext-{len(self.executions)}"
        return ConnectorActionResult(
            True, None, ref, {"ok": True}, now, 5, True, {"undo": action_type}
        )

    async def rollback(
        self, original_action_id: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult:
        del parameters, tenant_id
        now = datetime.now(UTC)
        return ConnectorActionResult(
            True, None, f"rb-{original_action_id}", {"rolled_back": True}, now, 3, False, {}
        )

    async def health_check(self, tenant_id: str) -> ConnectorHealthStatus:
        del tenant_id
        if self.fail_mode in {
            ConnectorFailureMode.NETWORK_FAILURE,
            ConnectorFailureMode.AUTH_FAILURE,
        }:
            return ConnectorHealthStatus.UNHEALTHY
        return ConnectorHealthStatus.HEALTHY

    async def verify_outcome(
        self, execution_id: str, step_number: int, tenant_id: str
    ) -> ConnectorActionResult | None:
        del tenant_id
        return self.verify_results.get(f"{execution_id}:{step_number}")
''',
    )
    w(
        base / "infrastructure" / "workers" / "connector_health_worker.py",
        '''from __future__ import annotations

from typing import Any
from uuid import UUID

from integration_hub.application.commands.connector_commands import TriggerHealthCheck


class ConnectorHealthWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.ticks = 0

    async def tick(self, tenant_id: UUID, roles: tuple[str, ...] = ("integration:admin",)) -> int:
        self.ticks += 1
        regs = await self._app.list_connectors(tenant_id, roles)
        checked = 0
        for reg in regs:
            if reg.status == "DISABLED":
                continue
            await self._app.health_check(
                TriggerHealthCheck(tenant_id, UUID(reg.connector_id), roles)
            )
            checked += 1
        return checked


class HealthScheduler:
    def __init__(self, worker: ConnectorHealthWorker) -> None:
        self.worker = worker

    async def tick(self, tenant_id: UUID) -> int:
        return await self.worker.tick(tenant_id)
''',
    )
    w(
        base / "infrastructure" / "observability" / "metrics_store.py",
        '''from __future__ import annotations


class OperationalMetricsStore:
    def __init__(self) -> None:
        self._counters: dict[str, float] = {}

    def incr(self, name: str, value: float = 1.0) -> None:
        self._counters[name] = self._counters.get(name, 0.0) + value

    def snapshot(self) -> dict[str, float]:
        return dict(self._counters)
''',
    )
    w(
        base / "infrastructure" / "container.py",
        '''from __future__ import annotations

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
''',
    )


def _api(base):
    w(
        base / "api" / "dependencies.py",
        '''from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from integration_hub.infrastructure.container import IntegrationHubContainer


def get_container(request: Request) -> IntegrationHubContainer:
    c = getattr(request.app.state, "integration_hub_container", None)
    if c is None:
        c = IntegrationHubContainer()
        request.app.state.integration_hub_container = c
    return c


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
''',
    )
    w(
        base / "api" / "v1" / "__init__.py",
        "from integration_hub.api.v1.routes import router\n\n__all__ = ['router']\n",
    )
    w(
        base / "api" / "v1" / "routes.py",
        '''from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from integration_hub.api.dependencies import get_container, roles_header, tenant_id_header
from integration_hub.application.commands.connector_commands import (
    DisableConnector,
    RegisterConnector,
    TriggerHealthCheck,
)
from integration_hub.application.exceptions import ApplicationForbiddenError, ApplicationNotFoundError
from integration_hub.domain.exceptions.domain_exceptions import IntegrationHubDomainError
from integration_hub.infrastructure.container import IntegrationHubContainer

router = APIRouter(prefix="/connectors", tags=["integration-hub"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, IntegrationHubDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class RegisterBody(BaseModel):
    connector_type: str
    display_name: str
    credential_vault_key: str
    credential_type: str
    registered_by: str = "api"
    configuration: dict[str, object] = Field(default_factory=dict)
    base_url: str | None = None


class DisableBody(BaseModel):
    disabled_by: str = "api"
    reason: str = "disabled"


@router.get("")
async def list_connectors(
    status_filter: str | None = None,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.list_connectors(tenant_id, roles, status_filter)
        return [r.__dict__ for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("", status_code=201)
async def register(
    body: RegisterBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.register(
            RegisterConnector(
                tenant_id,
                body.connector_type,
                body.display_name,
                body.credential_vault_key,
                body.credential_type,
                body.registered_by,
                roles,
                body.configuration,
                body.base_url,
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.delete("/{connector_id}")
async def disable(
    connector_id: UUID,
    body: DisableBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.disable(
            DisableConnector(tenant_id, connector_id, body.disabled_by, body.reason, roles)
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/{connector_id}/health")
async def health_history(
    connector_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return await container.app.health_history(tenant_id, connector_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{connector_id}/health-check")
async def health_check(
    connector_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.health_check(TriggerHealthCheck(tenant_id, connector_id, roles))
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc
''',
    )


def _tests() -> None:
    tbase = TESTS / "integration_hub"
    w(tbase / "__init__.py", "")
    w(
        tbase / "test_architecture.py",
        '''from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "integration_hub"
BANNED = re.compile(
    r"(api_key|secret|password|token|private_key|certificate)\\s*[:=]", re.I
)


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application" / "ports").is_dir()


def test_no_plaintext_secret_fields_in_aggregate_source() -> None:
    text = (ROOT / "domain" / "aggregates" / "connector_registration.py").read_text()
    # credential_ref / vault_key allowed; plaintext field assignments banned
    assert "credential_vault_key" not in text or "CredentialRef" in text
    for line in text.splitlines():
        if "banned" in line or "secret_keys" in line or "intersection" in line:
            continue
        if BANNED.search(line) and "CredentialRef" not in line:
            raise AssertionError(line)


def test_no_upstream_domain_imports() -> None:
    bad = re.compile(
        r"from (playbook|automated_action|detection|incident|engagement|exposure)\\."
    )
    for p in ROOT.rglob("*.py"):
        if bad.search(p.read_text()):
            raise AssertionError(p)
''',
    )
    w(
        tbase / "test_circuit_breaker.py",
        '''from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.services.circuit_breaker_service import CircuitBreakerService
from integration_hub.domain.value_objects.enums import CircuitState, ConnectorType
from integration_hub.domain.value_objects.identifiers import TenantId


def _reg() -> ConnectorRegistration:
    return ConnectorRegistration.register(
        TenantId(uuid4()),
        ConnectorType.CLOUD_AWS,
        "aws",
        "vault/aws",
        "API_KEY",
    )


def test_opens_after_threshold() -> None:
    svc = CircuitBreakerService()
    reg = _reg()
    base = datetime.now(UTC)
    for i in range(5):
        svc.record_failure(reg, at=base + timedelta(seconds=i))
    assert reg.circuit_state == CircuitState.OPEN


def test_half_open_then_close() -> None:
    svc = CircuitBreakerService()
    reg = _reg()
    opened = datetime.now(UTC) - timedelta(seconds=31)
    reg.apply_circuit(CircuitState.OPEN, 5, opened)
    assert svc.allow_request(reg)
    assert reg.circuit_state == CircuitState.HALF_OPEN
    svc.record_success(reg)
    assert reg.circuit_state == CircuitState.CLOSED


def test_half_open_failure_reopens() -> None:
    svc = CircuitBreakerService()
    reg = _reg()
    reg.apply_circuit(CircuitState.HALF_OPEN, 5, datetime.now(UTC))
    svc.record_failure(reg)
    assert reg.circuit_state == CircuitState.OPEN
''',
    )
    w(
        tbase / "test_connectors.py",
        '''from __future__ import annotations

import pytest

from integration_hub.domain.value_objects.enums import ConnectorFailureMode
from integration_hub.infrastructure.connectors.in_memory_action_connector import (
    InMemoryActionConnector,
)


@pytest.mark.parametrize("mode", list(ConnectorFailureMode))
@pytest.mark.asyncio
async def test_all_failure_modes(mode: ConnectorFailureMode) -> None:
    c = InMemoryActionConnector(fail_mode=mode)
    result = await c.execute("act", {}, "t1")
    assert result.success is False
    assert result.failure_mode == mode


@pytest.mark.asyncio
async def test_success_path() -> None:
    c = InMemoryActionConnector()
    result = await c.execute("contain_host", {"host": "h1"}, "t1")
    assert result.success is True
    assert result.external_reference
''',
    )
    w(
        tbase / "test_credentials.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest

from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.exceptions.domain_exceptions import DomainInvariantViolation
from integration_hub.domain.services.credential_resolution_service import (
    CredentialResolutionService,
)
from integration_hub.domain.value_objects.enums import ConnectorType
from integration_hub.domain.value_objects.identifiers import TenantId
from integration_hub.infrastructure.vault.in_memory_vault import InMemoryCredentialVault


def test_rejects_secret_config() -> None:
    with pytest.raises(DomainInvariantViolation):
        ConnectorRegistration.register(
            TenantId(uuid4()),
            ConnectorType.IDENTITY_OKTA,
            "okta",
            "vault/okta",
            "OAUTH_CLIENT",
            configuration={"api_key": "x"},
        )


@pytest.mark.asyncio
async def test_resolve_in_memory_only() -> None:
    vault = InMemoryCredentialVault()
    vault.put("k1", "super-secret")
    svc = CredentialResolutionService(vault)
    tenant = str(uuid4())
    from integration_hub.domain.value_objects.credentials import CredentialRef

    resolved = await svc.resolve(CredentialRef("k1", tenant, "API_KEY"), tenant)
    assert resolved.secret_value == "super-secret"
''',
    )
    w(
        tbase / "test_health_worker.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest

from integration_hub.application.commands.connector_commands import RegisterConnector
from integration_hub.infrastructure.container import IntegrationHubContainer


@pytest.mark.asyncio
async def test_health_worker_ticks() -> None:
    c = IntegrationHubContainer()
    tenant = uuid4()
    await c.app.register(
        RegisterConnector(
            tenant,
            "COMM_SLACK",
            "slack",
            "vault/slack",
            "API_KEY",
            "admin",
            ("integration:admin",),
        )
    )
    checked = await c.scheduler.tick(tenant)
    assert checked == 1
''',
    )
    w(
        tbase / "test_api.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from integration_hub.api.v1.routes import router
from integration_hub.infrastructure.container import IntegrationHubContainer


@pytest.mark.asyncio
async def test_register_list() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.integration_hub_container = IntegrationHubContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "integration:admin"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/connectors",
            json={
                "connector_type": "ITSM_JIRA",
                "display_name": "jira",
                "credential_vault_key": "v/jira",
                "credential_type": "API_KEY",
            },
            headers=headers,
        )
        assert r.status_code == 201
        lst = await client.get("/connectors", headers=headers)
        assert len(lst.json()) == 1
''',
    )
    w(
        tbase / "test_enums.py",
        '''from __future__ import annotations

import pytest

from integration_hub.domain.value_objects.enums import ConnectorFailureMode, ConnectorType


@pytest.mark.parametrize("value", list(ConnectorType))
def test_types(value: ConnectorType) -> None:
    assert value.value == value.name


def test_fifteen_types() -> None:
    assert len(ConnectorType) == 15


@pytest.mark.parametrize("value", list(ConnectorFailureMode))
def test_failure_modes(value: ConnectorFailureMode) -> None:
    assert value.value == value.name


def test_eight_failure_modes() -> None:
    assert len(ConnectorFailureMode) == 8
''',
    )
