from __future__ import annotations

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
