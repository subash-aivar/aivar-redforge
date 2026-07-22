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
    TriggerHealthCheck,
)
from integration_hub.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from integration_hub.domain.exceptions.domain_exceptions import IntegrationHubDomainError
from integration_hub.infrastructure.container import IntegrationHubContainer

# Namespaced to avoid collision with pre-existing platform /connectors router.
router = APIRouter(prefix="/integration-hub/connectors", tags=["integration-hub"])


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
