"""Connector & Discovery REST API — M3.

Tenant-scoped throughout. Discovery is inventory resolution ONLY — see
`TenantConnectorService`'s module docstring for the explicit
discovery-vs-active-validation boundary. This router does not, and must
never, expose an endpoint that executes an attack/exploit/pentest —
only register/enable/disable a connector and start/inspect discovery
runs.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_tenant_connector_service
from redforge.api.security import TenantContext, require_permission
from redforge.core.exceptions import NotFoundError, ValidationError
from redforge.domain.connectors.exceptions import ConnectorDomainError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.connectors.tenant_connector_service import (
        TenantConnectorService,
    )

router = APIRouter(prefix="/connectors", tags=["connectors"])


class RegisterConnectorRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)


class RegisterDirectoryConnectorRequest(BaseModel):
    """`credential_reference_id` is an environment-variable NAME (see
    `infrastructure/credential_resolver.py`) — never a raw bind
    password. If a browser cannot safely submit a credential this way,
    the credential must be configured through an approved server-side
    secret workflow — this API never accepts a plaintext password."""

    name: str = Field(..., min_length=2, max_length=100)
    server_uri: str = Field(..., min_length=8, max_length=255)
    base_dn: str = Field(..., min_length=1, max_length=255)
    bind_dn: str = Field(..., min_length=1, max_length=255)
    credential_reference_id: str = Field(..., min_length=1, max_length=100)
    use_start_tls: bool = False
    allow_insecure_plaintext: bool = False
    privileged_group_dns: list[str] = Field(default_factory=list, max_length=50)
    description: str = Field(default="", max_length=500)


class RegisterNetworkConnectorRequest(BaseModel):
    """Bounded, read-only TCP-connect network discovery. `network_cidr`
    and `ports` are validated again server-side at scan time
    (`BoundedNetworkScanAdapter`) — this request model's own field
    limits are a first line of defense, not the only one."""

    name: str = Field(..., min_length=2, max_length=100)
    network_cidr: str = Field(..., min_length=1, max_length=64)
    ports: list[int] = Field(..., min_length=1, max_length=20)
    description: str = Field(default="", max_length=500)


class RegisterCloudConnectorRequest(BaseModel):
    """Real, read-only AWS discovery. `secret_access_key_credential_reference_id`
    (and the optional session-token reference) are environment-variable
    NAMEs — never the raw secret value; this API never accepts or
    returns AWS secret material."""

    name: str = Field(..., min_length=2, max_length=100)
    region: str = Field(..., min_length=1, max_length=32)
    access_key_id: str = Field(..., min_length=1, max_length=128)
    secret_access_key_credential_reference_id: str = Field(..., min_length=1, max_length=100)
    session_token_credential_reference_id: str | None = Field(default=None, max_length=100)
    description: str = Field(default="", max_length=500)


class ConnectorResponse(BaseModel):
    id: str
    organization_id: str
    connector_type: str
    name: str
    status: str
    last_discovery_status: str | None
    last_discovery_completed_at: str | None
    created_at: str
    updated_at: str


class DiscoveryRunResponse(BaseModel):
    job_id: str
    connector_id: str
    status: str
    started_at: str
    completed_at: str | None
    assets_discovered: int
    assets_normalized: int
    assets_failed: int
    error_message: str | None


@router.post("", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED)
async def register_connector(
    body: RegisterConnectorRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> ConnectorResponse:
    """Registers the RedForge-Targets discovery connector for the
    caller's organization — the only connector type M3 ships as a real
    (non-simulated) reference adapter.
    """
    connector = await service.register(tenant.organization_id, body.name, body.description)
    return ConnectorResponse(**dataclasses.asdict(connector))


@router.post(
    "/directory", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED,
)
async def register_directory_connector(
    body: RegisterDirectoryConnectorRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> ConnectorResponse:
    """Registers a real, read-only LDAP/Active-Directory-compatible
    directory connector (M5). Discovery under this connector is
    visibility only — see `LdapDirectoryAdapter`'s documented read-only
    safety boundary; no write/mutate directory operation is ever
    exposed."""
    try:
        connector = await service.register_directory_connector(
            organization_id=tenant.organization_id,
            name=body.name,
            server_uri=body.server_uri,
            base_dn=body.base_dn,
            bind_dn=body.bind_dn,
            credential_reference_id=body.credential_reference_id,
            use_start_tls=body.use_start_tls,
            allow_insecure_plaintext=body.allow_insecure_plaintext,
            privileged_group_dns=tuple(body.privileged_group_dns),
            description=body.description,
        )
    except ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc
    return ConnectorResponse(**dataclasses.asdict(connector))


@router.post(
    "/network", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED,
)
async def register_network_connector(
    body: RegisterNetworkConnectorRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> ConnectorResponse:
    """Registers a bounded, read-only TCP-connect network discovery
    connector (M6). Registration itself does not validate scope policy
    (0.0.0.0/0, oversized ranges) — that check runs at scan time in
    `BoundedNetworkScanAdapter`, so a connector can be registered with
    any input but discovery will reject an out-of-policy scope."""
    connector = await service.register_network_connector(
        organization_id=tenant.organization_id,
        name=body.name,
        network_cidr=body.network_cidr,
        ports=tuple(body.ports),
        description=body.description,
    )
    return ConnectorResponse(**dataclasses.asdict(connector))


@router.post(
    "/cloud", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED,
)
async def register_cloud_connector(
    body: RegisterCloudConnectorRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> ConnectorResponse:
    """Registers a real, read-only AWS discovery connector (M7). Only
    AWS is implemented — Azure/GCP are not (see the M7 report's honest
    disposition). No mutation/delete/policy-change AWS capability is
    ever exposed."""
    connector = await service.register_cloud_connector(
        organization_id=tenant.organization_id,
        name=body.name,
        region=body.region,
        access_key_id=body.access_key_id,
        secret_access_key_credential_reference_id=body.secret_access_key_credential_reference_id,
        session_token_credential_reference_id=body.session_token_credential_reference_id,
        description=body.description,
    )
    return ConnectorResponse(**dataclasses.asdict(connector))


@router.get("", response_model=list[ConnectorResponse])
async def list_connectors(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> list[ConnectorResponse]:
    connectors = await service.list_for_org(tenant.organization_id)
    return [ConnectorResponse(**dataclasses.asdict(c)) for c in connectors]


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> ConnectorResponse:
    try:
        connector = await service.get_for_org(connector_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return ConnectorResponse(**dataclasses.asdict(connector))


@router.post("/{connector_id}/disable", response_model=ConnectorResponse)
async def disable_connector(
    connector_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> ConnectorResponse:
    try:
        connector = await service.disable(connector_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    except ConnectorDomainError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return ConnectorResponse(**dataclasses.asdict(connector))


@router.post("/{connector_id}/enable", response_model=ConnectorResponse)
async def enable_connector(
    connector_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> ConnectorResponse:
    try:
        connector = await service.enable(connector_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    except ConnectorDomainError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return ConnectorResponse(**dataclasses.asdict(connector))


@router.post(
    "/{connector_id}/discover",
    response_model=DiscoveryRunResponse,
    status_code=status.HTTP_201_CREATED,
)
async def start_discovery(
    connector_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_MANAGE)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> DiscoveryRunResponse:
    """Starts a discovery run. Rejected if the connector is disabled,
    owned by another organization, or already has a discovery job
    running — all enforced by the `Connector` domain aggregate itself.
    """
    try:
        run = await service.start_discovery(connector_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    except ValidationError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=exc.message) from exc
    return DiscoveryRunResponse(**dataclasses.asdict(run))


@router.get("/{connector_id}/discovery-runs", response_model=list[DiscoveryRunResponse])
async def list_discovery_runs(
    connector_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantConnectorService = Depends(get_tenant_connector_service),
) -> list[DiscoveryRunResponse]:
    try:
        runs = await service.list_discovery_runs(connector_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return [DiscoveryRunResponse(**dataclasses.asdict(r)) for r in runs]
