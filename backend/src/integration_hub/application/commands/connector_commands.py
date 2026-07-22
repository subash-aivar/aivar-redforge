from __future__ import annotations

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
