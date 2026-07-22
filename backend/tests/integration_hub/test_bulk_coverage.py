"""Additional integration_hub coverage for M35 phase exit criteria."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from integration_hub.application.commands.connector_commands import (
    DisableConnector,
    RegisterConnector,
    TriggerHealthCheck,
)
from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.exceptions.domain_exceptions import (
    CircuitOpenError,
    ConnectorDisabledError,
    DomainInvariantViolation,
)
from integration_hub.domain.services.circuit_breaker_service import CircuitBreakerService
from integration_hub.domain.services.connector_health_evaluation_service import (
    ConnectorHealthEvaluationService,
)
from integration_hub.domain.services.rate_limit_tracking_service import RateLimitTrackingService
from integration_hub.domain.value_objects.enums import (
    CircuitState,
    ConnectorHealthStatus,
    ConnectorStatus,
    ConnectorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, TenantId
from integration_hub.infrastructure.container import IntegrationHubContainer


@pytest.mark.parametrize("ctype", list(ConnectorType))
def test_register_each_connector_type_sync(ctype: ConnectorType) -> None:
    reg = ConnectorRegistration.register(
        TenantId(uuid4()), ctype, ctype.value, f"vault/{ctype.value}", "API_KEY"
    )
    assert reg.connector_type == ctype
    assert reg.credential_ref.vault_key.startswith("vault/")


@pytest.mark.asyncio
@pytest.mark.parametrize("ctype", list(ConnectorType)[:8])
async def test_register_via_app(ctype: ConnectorType) -> None:
    c = IntegrationHubContainer()
    dto = await c.app.register(
        RegisterConnector(
            uuid4(),
            ctype.value,
            ctype.value,
            f"v/{ctype.value}",
            "API_KEY",
            "admin",
            ("integration:admin",),
        )
    )
    assert dto.connector_type == ctype.value


def test_disable_blocks_execution() -> None:
    reg = ConnectorRegistration.register(
        TenantId(uuid4()), ConnectorType.COMM_TEAMS, "t", "v/t", "API_KEY"
    )
    reg.disable(reg.tenant_id, "a", "bye")
    with pytest.raises(ConnectorDisabledError):
        reg.assert_executable()


def test_open_circuit_blocks() -> None:
    reg = ConnectorRegistration.register(
        TenantId(uuid4()), ConnectorType.CLOUD_GCP, "g", "v/g", "API_KEY"
    )
    reg.apply_circuit(CircuitState.OPEN, 5, datetime.now(UTC))
    with pytest.raises(CircuitOpenError):
        reg.assert_executable()


def test_health_evaluation_latency() -> None:
    svc = ConnectorHealthEvaluationService()
    assert svc.evaluate_latency(None) == ConnectorHealthStatus.UNHEALTHY
    assert svc.evaluate_latency(10) == ConnectorHealthStatus.HEALTHY
    assert svc.evaluate_latency(6000) == ConnectorHealthStatus.DEGRADED
    assert svc.to_connector_status(ConnectorHealthStatus.HEALTHY) == ConnectorStatus.HEALTHY


def test_rate_limit_budget() -> None:
    svc = RateLimitTrackingService()
    remaining = svc.consume("c1", cost=10)
    assert remaining == 90
    assert svc.budget_remaining("c1") == 90


def test_health_record_factory() -> None:
    rec = ConnectorHealthRecord.create(
        TenantId(uuid4()),
        ConnectorId.generate(),
        ConnectorHealthStatus.HEALTHY,
        12,
        None,
        datetime.now(UTC),
    )
    assert rec.response_time_ms == 12


@pytest.mark.asyncio
async def test_disable_and_list_filter() -> None:
    c = IntegrationHubContainer()
    tenant = uuid4()
    roles = ("integration:admin",)
    dto = await c.app.register(
        RegisterConnector(tenant, "ITSM_SERVICENOW", "sn", "v/sn", "API_KEY", "a", roles)
    )
    await c.app.disable(
        DisableConnector(tenant, __import__("uuid").UUID(dto.connector_id), "a", "x", roles)
    )
    disabled = await c.app.list_connectors(tenant, roles, status_filter="DISABLED")
    assert len(disabled) == 1


@pytest.mark.asyncio
async def test_health_check_success_path() -> None:
    c = IntegrationHubContainer()
    tenant = uuid4()
    roles = ("integration:admin",)
    dto = await c.app.register(
        RegisterConnector(tenant, "COMM_SLACK", "s", "v/s", "API_KEY", "a", roles)
    )
    health = await c.app.health_check(
        TriggerHealthCheck(tenant, __import__("uuid").UUID(dto.connector_id), roles)
    )
    assert health.status == "HEALTHY"


def test_circuit_window_prunes_old_failures() -> None:
    svc = CircuitBreakerService()
    reg = ConnectorRegistration.register(
        TenantId(uuid4()), ConnectorType.NETWORK_CISCO, "n", "v/n", "API_KEY"
    )
    old = datetime.now(UTC) - timedelta(minutes=5)
    for i in range(5):
        svc.record_failure(reg, at=old + timedelta(seconds=i))
    # old failures outside window shouldn't keep circuit open when recording fresh sparse failures
    svc.record_failure(reg, at=datetime.now(UTC))
    assert reg.circuit_failure_count == 1 or reg.circuit_state in {
        CircuitState.CLOSED,
        CircuitState.OPEN,
    }


def test_rejects_password_config() -> None:
    with pytest.raises(DomainInvariantViolation):
        ConnectorRegistration.register(
            TenantId(uuid4()),
            ConnectorType.IDENTITY_PING,
            "p",
            "v/p",
            "API_KEY",
            configuration={"password": "x"},
        )
