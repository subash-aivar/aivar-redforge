"""Connector plugin descriptor — the unit of extension for the Integration Hub.

A `ConnectorPlugin` is pure metadata + a factory. Adding a new connector
means writing one plugin module and registering it in
`infrastructure/plugin_catalog.py` — no changes to the aggregate, the
application service, the API routes, or the frontend wizard, all of
which are driven generically off this descriptor.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum

from integration_hub.domain.value_objects.enums import ConnectorHealthStatus


class ConnectorCategory(StrEnum):
    AI = "AI"
    CLOUD = "CLOUD"
    IDENTITY = "IDENTITY"
    DEVELOPMENT = "DEVELOPMENT"
    COMMUNICATION = "COMMUNICATION"
    NETWORKING = "NETWORKING"
    ITSM = "ITSM"


class AuthModel(StrEnum):
    """Real-world vendor authentication models — never invented per connector."""

    API_KEY = "API_KEY"
    OAUTH2_CLIENT_CREDENTIALS = "OAUTH2_CLIENT_CREDENTIALS"
    OAUTH2_AUTHORIZATION_CODE = "OAUTH2_AUTHORIZATION_CODE"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"
    IAM_ROLE = "IAM_ROLE"
    PERSONAL_ACCESS_TOKEN = "PERSONAL_ACCESS_TOKEN"
    SSH_KEY = "SSH_KEY"
    CLIENT_CERTIFICATE = "CLIENT_CERTIFICATE"
    SAML = "SAML"
    OIDC = "OIDC"
    NONE = "NONE"


@dataclass(frozen=True, slots=True)
class CredentialFieldSpec:
    """One secret field the admin must supply — stored in credential_vault,
    never inline in connector configuration."""

    name: str
    label: str
    vault_category: str  # credential_vault CredentialCategory value
    vault_subtype: str
    required: bool = True
    help_text: str = ""
    is_multiline: bool = False


@dataclass(frozen=True, slots=True)
class ConfigFieldSpec:
    """One non-secret configuration field (region, tenant id, endpoint, ...)."""

    name: str
    label: str
    required: bool = True
    default: str | None = None
    help_text: str = ""


@dataclass(frozen=True, slots=True)
class ConnectorDocs:
    """The 12-section administrator documentation, rendered by the frontend
    wizard/detail drawer — never left for the admin to look up externally."""

    purpose: str
    supported_features: list[str]
    required_credentials: str
    required_permissions: str
    required_vendor_configuration: str
    validation_process: str
    connectivity_test: str
    health_check: str
    synchronization_strategy: str
    troubleshooting_guide: str
    common_failure_scenarios: str
    recovery_steps: str
    required_scopes: list[str] = field(default_factory=list)
    callback_urls: list[str] = field(default_factory=list)
    firewall_notes: str = ""


HealthCheckFn = Callable[[str, dict[str, str]], Awaitable[ConnectorHealthStatus]]


@dataclass(frozen=True, slots=True)
class ConnectorPlugin:
    """Registered once at startup via ConnectorPluginCatalog.register()."""

    connector_id: str
    display_name: str
    category: ConnectorCategory
    auth_model: AuthModel
    credential_fields: list[CredentialFieldSpec]
    config_fields: list[ConfigFieldSpec]
    docs: ConnectorDocs
    health_check: HealthCheckFn
    """health_check(secret, config) -> ConnectorHealthStatus. `secret` is the
    resolved plaintext from credential_vault for this connector instance's
    primary credential field; `config` is the registration's non-secret
    configuration dict."""
