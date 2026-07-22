from __future__ import annotations

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
