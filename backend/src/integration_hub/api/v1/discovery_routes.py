from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from integration_hub.api.dependencies import get_container, roles_header, tenant_id_header
from integration_hub.application.commands.discovery_commands import CancelDiscovery, RunDiscovery
from integration_hub.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from integration_hub.domain.exceptions.domain_exceptions import IntegrationHubDomainError
from integration_hub.domain.value_objects.identifiers import TenantId
from integration_hub.infrastructure.container import IntegrationHubContainer

# Namespaced alongside the connectors/catalog routers in this BC.
discovery_router = APIRouter(prefix="/integration-hub/connectors", tags=["integration-hub"])
assets_router = APIRouter(prefix="/integration-hub/assets", tags=["integration-hub"])


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


class RunDiscoveryBody(BaseModel):
    mode: str = "MANUAL"
    triggered_by: str = "api"
    resume_sync_run_id: UUID | None = None
    max_pages: int = 25


@discovery_router.post("/{connector_id}/discovery/run", status_code=201)
async def run_discovery(
    connector_id: UUID,
    body: RunDiscoveryBody,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.discovery.run_discovery(
            RunDiscovery(
                tenant_id,
                connector_id,
                body.mode,
                body.triggered_by,
                roles,
                resume_sync_run_id=body.resume_sync_run_id,
                max_pages=body.max_pages,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@discovery_router.post("/{connector_id}/discovery/{sync_run_id}/cancel")
async def cancel_discovery(
    connector_id: UUID,
    sync_run_id: UUID,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.discovery.cancel_discovery(
            CancelDiscovery(tenant_id, connector_id, sync_run_id, roles)
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@discovery_router.get("/{connector_id}/discovery/history")
async def discovery_history(
    connector_id: UUID,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.discovery.list_sync_runs(tenant_id, connector_id, roles)
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@assets_router.get("")
async def list_assets(
    category: str | None = None,
    vendor: str | None = None,
    tag: str | None = None,
    limit: int = 100,
    offset: int = 0,
    order_by: str = "-discovered_at",
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.discovery.list_assets(
            tenant_id,
            roles,
            category=category,
            vendor=vendor,
            tag=tag,
            limit=limit,
            offset=offset,
            order_by=order_by,
        )
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@assets_router.get("/{asset_id}")
async def get_asset(
    asset_id: UUID,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.discovery.get_asset(tenant_id, asset_id, roles)
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@assets_router.get("/{asset_id}/relationships")
async def list_relationships(
    asset_id: UUID,
    tenant_id: TenantId = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: IntegrationHubContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.discovery.list_relationships(tenant_id, asset_id, roles)
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc
