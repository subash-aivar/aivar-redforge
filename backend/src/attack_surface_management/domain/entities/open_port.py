"""OpenPort entity (M49A) — a single network port observed on an
`Asset`, individually identified so that a port can be closed/reopened
and re-fingerprinted over time without disturbing the asset's other
ports. Owned exclusively within the `Asset` aggregate; never referenced
by id from outside it. Modeled as a frozen dataclass whose identity
(`port_id`) is preserved across state transitions via
`dataclasses.replace` — the same "identity-preserving replace" pattern
`cloud_security.CloudAsset` uses for its tag collection."""

from __future__ import annotations

import dataclasses
from datetime import datetime

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidPortNumberError,
)
from attack_surface_management.domain.value_objects.enums import PortProtocol, PortState
from attack_surface_management.domain.value_objects.identifiers import PortId
from attack_surface_management.domain.value_objects.service_banner import ServiceBanner

_HIGH_RISK_PORTS = frozenset({21, 23, 445, 3389, 5900})


@dataclasses.dataclass(frozen=True, slots=True)
class OpenPort:
    port_id: PortId
    port_number: int
    protocol: PortProtocol
    state: PortState
    detected_at: datetime
    service: ServiceBanner | None = None

    def __post_init__(self) -> None:
        if not (0 <= self.port_number <= 65535):
            raise InvalidPortNumberError(self.port_number)

    @property
    def is_high_risk(self) -> bool:
        """A port is high-risk if it is a conventionally dangerous
        service port, or its identified service is itself flagged
        high-risk (covers non-standard port assignments)."""
        if self.port_number in _HIGH_RISK_PORTS:
            return True
        return bool(self.service and self.service.is_high_risk_service)

    def close(self, now: datetime) -> OpenPort:
        return dataclasses.replace(self, state=PortState.CLOSED, detected_at=now)

    def with_service(self, service: ServiceBanner, now: datetime) -> OpenPort:
        return dataclasses.replace(self, service=service, detected_at=now)
