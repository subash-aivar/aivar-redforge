"""Circuit breaker — ADR-M35-006."""

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

    def record_failure(
        self, registration: ConnectorRegistration, *, at: datetime | None = None
    ) -> None:
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

    def maybe_half_open(
        self, registration: ConnectorRegistration, *, at: datetime | None = None
    ) -> None:
        now = at or datetime.now(UTC)
        if registration.circuit_state != CircuitState.OPEN:
            return
        if (
            registration.circuit_opened_at
            and now - registration.circuit_opened_at >= self.OPEN_DURATION
        ):
            registration.apply_circuit(
                CircuitState.HALF_OPEN,
                registration.circuit_failure_count,
                registration.circuit_opened_at,
            )

    def allow_request(
        self, registration: ConnectorRegistration, *, at: datetime | None = None
    ) -> bool:
        self.maybe_half_open(registration, at=at)
        return registration.circuit_state != CircuitState.OPEN
