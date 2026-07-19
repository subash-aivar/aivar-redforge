"""Credential policies API router."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Response, status

from credential_vault.api.dependencies import (
    ExpirationPolicyServiceDep,
    PrincipalIdDep,
    RotationPolicyServiceDep,
    TenantIdDep,
)
from credential_vault.api.schemas.policy_schemas import (
    CreateExpirationPolicyRequest,
    CreateRotationPolicyRequest,
    ExpirationPolicyResponse,
    RotationPolicyResponse,
    UpdateExpirationPolicyRequest,
    UpdateRotationPolicyRequest,
)
from credential_vault.application.commands.policy_commands import (
    CreateExpirationPolicyCommand,
    CreateRotationPolicyCommand,
    DeleteExpirationPolicyCommand,
    DeleteRotationPolicyCommand,
    UpdateExpirationPolicyCommand,
    UpdateRotationPolicyCommand,
)
from credential_vault.application.queries.policy_queries import (
    GetExpirationPolicyQuery,
    GetRotationPolicyQuery,
    ListExpirationPoliciesQuery,
    ListRotationPoliciesQuery,
)

router = APIRouter()


@router.post(
    "/rotation", status_code=status.HTTP_201_CREATED, response_model=RotationPolicyResponse
)
async def create_rotation_policy(
    body: CreateRotationPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RotationPolicyServiceDep,
) -> RotationPolicyResponse:
    dto = await svc.create_rotation_policy(
        CreateRotationPolicyCommand(
            tenant_id=tenant_id,
            principal_id=principal_id,
            name=body.name,
            interval_days=body.interval_days,
            max_versions_kept=body.max_versions_kept,
            notify_days_before=body.notify_days_before,
            auto_rotate=body.auto_rotate,
            auto_commit=body.auto_commit,
            commit_window_hours=body.commit_window_hours,
        )
    )
    return RotationPolicyResponse.from_dto(dto)


@router.get("/rotation/{policy_id}", response_model=RotationPolicyResponse)
async def get_rotation_policy(
    policy_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RotationPolicyServiceDep,
) -> RotationPolicyResponse:
    dto = await svc.get_rotation_policy(GetRotationPolicyQuery(tenant_id, policy_id, principal_id))
    return RotationPolicyResponse.from_dto(dto)


@router.get("/rotation", response_model=list[RotationPolicyResponse])
async def list_rotation_policies(
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RotationPolicyServiceDep,
) -> list[RotationPolicyResponse]:
    items = await svc.list_rotation_policies(ListRotationPoliciesQuery(tenant_id, principal_id))
    return [RotationPolicyResponse.from_dto(item) for item in items]


@router.patch("/rotation/{policy_id}", response_model=RotationPolicyResponse)
async def update_rotation_policy(
    policy_id: UUID,
    body: UpdateRotationPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RotationPolicyServiceDep,
) -> RotationPolicyResponse:
    dto = await svc.update_rotation_policy(
        UpdateRotationPolicyCommand(
            tenant_id,
            policy_id,
            principal_id,
            body.interval_days,
            body.max_versions_kept,
            body.notify_days_before,
            body.auto_rotate,
            body.auto_commit,
            body.commit_window_hours,
        )
    )
    return RotationPolicyResponse.from_dto(dto)


@router.delete("/rotation/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rotation_policy(
    policy_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RotationPolicyServiceDep,
) -> Response:
    await svc.delete_rotation_policy(
        DeleteRotationPolicyCommand(tenant_id, policy_id, principal_id)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/expiration",
    status_code=status.HTTP_201_CREATED,
    response_model=ExpirationPolicyResponse,
)
async def create_expiration_policy(
    body: CreateExpirationPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExpirationPolicyServiceDep,
) -> ExpirationPolicyResponse:
    dto = await svc.create_expiration_policy(
        CreateExpirationPolicyCommand(
            tenant_id,
            principal_id,
            body.name,
            body.ttl_days,
            body.warn_days_before,
            body.hard_expire,
        )
    )
    return ExpirationPolicyResponse.from_dto(dto)


@router.get("/expiration/{policy_id}", response_model=ExpirationPolicyResponse)
async def get_expiration_policy(
    policy_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExpirationPolicyServiceDep,
) -> ExpirationPolicyResponse:
    dto = await svc.get_expiration_policy(
        GetExpirationPolicyQuery(tenant_id, policy_id, principal_id)
    )
    return ExpirationPolicyResponse.from_dto(dto)


@router.get("/expiration", response_model=list[ExpirationPolicyResponse])
async def list_expiration_policies(
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExpirationPolicyServiceDep,
) -> list[ExpirationPolicyResponse]:
    items = await svc.list_expiration_policies(ListExpirationPoliciesQuery(tenant_id, principal_id))
    return [ExpirationPolicyResponse.from_dto(item) for item in items]


@router.patch("/expiration/{policy_id}", response_model=ExpirationPolicyResponse)
async def update_expiration_policy(
    policy_id: UUID,
    body: UpdateExpirationPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExpirationPolicyServiceDep,
) -> ExpirationPolicyResponse:
    dto = await svc.update_expiration_policy(
        UpdateExpirationPolicyCommand(
            tenant_id,
            policy_id,
            principal_id,
            body.ttl_days,
            body.warn_days_before,
            body.hard_expire,
        )
    )
    return ExpirationPolicyResponse.from_dto(dto)


@router.delete("/expiration/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_expiration_policy(
    policy_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExpirationPolicyServiceDep,
) -> Response:
    await svc.delete_expiration_policy(
        DeleteExpirationPolicyCommand(tenant_id, policy_id, principal_id)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
