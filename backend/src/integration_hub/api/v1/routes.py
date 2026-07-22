from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from integration_hub.api.dependencies import get_container, roles_header, tenant_id_header
from integration_hub.application.commands.connector_commands import (
    DisableConnector,
    RegisterConnector,
    RegisterConnectorWithCredential,
    TriggerHealthCheck,
)
from integration_hub.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from integration_hub.domain.exceptions.domain_exceptions import IntegrationHubDomainError
from integration_hub.infrastructure.container import IntegrationHubContainer

# Namespaced to avoid collision with pre-existing platform /connectors router.
router = APIRouter(prefix="/integration-hub/connectors", tags=["integration-hub"])
catalog_router = APIRouter(prefix="/integration-hub/catalog", tags=["integration-hub"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ApplicationValidationError):
        return HTTPException(status_code=400, detail=str(exc))
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


class RegisterWithCredentialBody(BaseModel):
    """Setup-wizard registration: the platform stores the secret in
    credential_vault itself — plaintext_secret is never persisted outside
    the vault and never logged."""

    connector_id: str
    display_name: str
    plaintext_secret: str
    vault_backend_id: UUID
    owner_principal_id: UUID
    registered_by: str = "api"
    configuration: dict[str, object] = Field(default_factory=dict)


class DisableBody(BaseModel):
    disabled_by: str = "api"
    reason: str = "disabled"


@catalog_router.get("")
async def list_catalog(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    """Available connector plugins for the setup wizard — no auth beyond a
    valid session; this is catalog metadata, not tenant data."""
    plugins = container.app.list_catalog()
    return [
        {
            "connector_id": p.connector_id,
            "display_name": p.display_name,
            "category": p.category.value,
            "auth_model": p.auth_model.value,
            "credential_fields": [
                {
                    "name": f.name,
                    "label": f.label,
                    "required": f.required,
                    "help_text": f.help_text,
                    "is_multiline": f.is_multiline,
                }
                for f in p.credential_fields
            ],
            "config_fields": [
                {
                    "name": f.name,
                    "label": f.label,
                    "required": f.required,
                    "default": f.default,
                    "help_text": f.help_text,
                }
                for f in p.config_fields
            ],
            "docs": {
                "purpose": p.docs.purpose,
                "supported_features": p.docs.supported_features,
                "required_credentials": p.docs.required_credentials,
                "required_permissions": p.docs.required_permissions,
                "required_vendor_configuration": p.docs.required_vendor_configuration,
                "validation_process": p.docs.validation_process,
                "connectivity_test": p.docs.connectivity_test,
                "health_check": p.docs.health_check,
                "synchronization_strategy": p.docs.synchronization_strategy,
                "troubleshooting_guide": p.docs.troubleshooting_guide,
                "common_failure_scenarios": p.docs.common_failure_scenarios,
                "recovery_steps": p.docs.recovery_steps,
                "required_scopes": p.docs.required_scopes,
                "callback_urls": p.docs.callback_urls,
                "firewall_notes": p.docs.firewall_notes,
            },
        }
        for p in plugins
    ]


@router.get("")
async def list_connectors(
    status_filter: str | None = None,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.list_connectors(tenant_id, roles, status_filter)
        return [asdict(r) for r in rows]
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
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/register-with-credential", status_code=201)
async def register_with_credential(
    body: RegisterWithCredentialBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    """Setup-wizard registration path: creates the secret in
    credential_vault and registers the connector in one step."""
    try:
        dto = await container.app.register_with_credential(
            RegisterConnectorWithCredential(
                tenant_id,
                body.connector_id,
                body.display_name,
                body.plaintext_secret,
                body.vault_backend_id,
                body.owner_principal_id,
                body.registered_by,
                roles,
                body.configuration,
            )
        )
        return asdict(dto)
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
        return asdict(dto)
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
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/{connector_id}/test-connection")
async def test_connection(
    connector_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    """Synchronous connectivity test for immediate wizard feedback — same
    underlying check as the periodic health monitor."""
    try:
        dto = await container.app.health_check(TriggerHealthCheck(tenant_id, connector_id, roles))
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc
