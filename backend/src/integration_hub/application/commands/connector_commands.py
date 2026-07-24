from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from integration_hub.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class RegisterConnector:
    tenant_id: TenantId
    connector_type: str
    display_name: str
    credential_vault_key: str
    credential_type: str
    registered_by: str
    roles: tuple[str, ...]
    configuration: dict[str, object] | None = None
    base_url: str | None = None


@dataclass(frozen=True, slots=True)
class RegisterConnectorWithCredential:
    """Self-service registration: the platform creates the credential_vault
    entry itself from the plaintext secret submitted through the setup
    wizard, then registers the connector holding only the vault pointer.
    The plaintext secret is never persisted outside credential_vault."""

    tenant_id: TenantId
    connector_id: str  # ConnectorPluginCatalog key, e.g. "openai"
    display_name: str
    plaintext_secret: str
    vault_backend_id: UUID
    owner_principal_id: UUID
    registered_by: str
    roles: tuple[str, ...]
    configuration: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class DisableConnector:
    tenant_id: TenantId
    connector_id: UUID
    disabled_by: str
    reason: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TriggerHealthCheck:
    tenant_id: TenantId
    connector_id: UUID
    roles: tuple[str, ...]
