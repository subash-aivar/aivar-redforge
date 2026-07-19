"""Vault backends API router."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Response, status

from credential_vault.api.dependencies import (
    PrincipalIdDep,
    TenantIdDep,
    VaultBackendServiceDep,
)
from credential_vault.api.schemas.backend_schemas import (
    RegisterVaultBackendRequest,
    VaultBackendResponse,
)
from credential_vault.application.commands.backend_commands import (
    DeleteVaultBackendCommand,
    RegisterVaultBackendCommand,
)
from credential_vault.application.queries.backend_queries import (
    GetVaultBackendQuery,
    ListVaultBackendsQuery,
)

router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED, response_model=VaultBackendResponse)
async def register_vault_backend(
    body: RegisterVaultBackendRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: VaultBackendServiceDep,
) -> VaultBackendResponse:
    dto = await svc.register_vault_backend(
        RegisterVaultBackendCommand(
            tenant_id,
            principal_id,
            body.name,
            body.backend_type,
            body.config,
            body.is_default,
        )
    )
    return VaultBackendResponse.from_dto(dto)


@router.get("/{backend_id}", response_model=VaultBackendResponse)
async def get_vault_backend(
    backend_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: VaultBackendServiceDep,
) -> VaultBackendResponse:
    dto = await svc.get_vault_backend(GetVaultBackendQuery(tenant_id, backend_id, principal_id))
    return VaultBackendResponse.from_dto(dto)


@router.get("", response_model=list[VaultBackendResponse])
async def list_vault_backends(
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: VaultBackendServiceDep,
) -> list[VaultBackendResponse]:
    items = await svc.list_vault_backends(ListVaultBackendsQuery(tenant_id, principal_id))
    return [VaultBackendResponse.from_dto(item) for item in items]


@router.delete("/{backend_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vault_backend(
    backend_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: VaultBackendServiceDep,
) -> Response:
    await svc.delete_vault_backend(DeleteVaultBackendCommand(tenant_id, backend_id, principal_id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
