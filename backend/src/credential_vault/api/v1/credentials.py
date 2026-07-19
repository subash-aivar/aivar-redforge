"""Credentials API router."""

from __future__ import annotations

import base64
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query, Response, status

from credential_vault.api.dependencies import (
    CredentialQueryServiceDep,
    CredentialServiceDep,
    PrincipalIdDep,
    TenantIdDep,
)
from credential_vault.api.schemas.credential_schemas import (
    AttachExpirationPolicyRequest,
    AttachRotationPolicyRequest,
    CreateCredentialRequest,
    CredentialResponse,
    DetachPolicyRequest,
    DisableCredentialRequest,
    EmergencyRevokeRequest,
    ListCredentialsResponse,
    ListVersionsResponse,
    RecoverCredentialRequest,
    ResolveCredentialRequest,
    ResolveCredentialResponse,
    RevokeCredentialRequest,
    RollbackVersionRequest,
    RotateCredentialRequest,
    UpdateCredentialMetadataRequest,
    VersionResponse,
)
from credential_vault.application.commands.credential_commands import (
    AbortRotationCommand,
    AttachExpirationPolicyCommand,
    AttachRotationPolicyCommand,
    CommitRotationCommand,
    CreateCredentialCommand,
    DetachExpirationPolicyCommand,
    DetachRotationPolicyCommand,
    DisableCredentialCommand,
    EmergencyRevokeCommand,
    EnableCredentialCommand,
    HardDeleteCredentialCommand,
    RecoverCredentialCommand,
    ResolveCredentialCommand,
    RevokeCredentialCommand,
    RollbackVersionCommand,
    RotateCredentialCommand,
    UpdateCredentialMetadataCommand,
)
from credential_vault.application.queries.credential_queries import (
    GetCredentialQuery,
    GetVersionQuery,
    ListCredentialsQuery,
    ListVersionsQuery,
)

router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED, response_model=CredentialResponse)
async def create_credential(
    body: CreateCredentialRequest,
    response: Response,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    cmd = CreateCredentialCommand(
        tenant_id=tenant_id,
        name=body.name,
        category=body.category,
        subtype=body.subtype,
        schema_id=body.schema_id,
        owner_principal_id=principal_id,
        vault_backend_id=body.vault_backend_id,
        plaintext_secret=body.plaintext_secret.encode("utf-8"),
        description=body.description,
        tags=body.tags,
        expires_at=body.expires_at,
    )
    dto = await svc.create_credential(cmd)
    response.headers["Location"] = f"/api/v1/credentials/{dto.credential_id}"
    return CredentialResponse.from_dto(dto)


@router.get("/{credential_id}", response_model=CredentialResponse)
async def get_credential(
    credential_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    query_svc: CredentialQueryServiceDep,
) -> CredentialResponse:
    dto = await query_svc.get_credential(GetCredentialQuery(tenant_id, credential_id, principal_id))
    return CredentialResponse.from_dto(dto)


@router.get("", response_model=ListCredentialsResponse)
async def list_credentials(
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    query_svc: CredentialQueryServiceDep,
    states: list[str] | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> ListCredentialsResponse:
    items = await query_svc.list_credentials(
        ListCredentialsQuery(tenant_id, principal_id, states, limit, offset)
    )
    return ListCredentialsResponse(
        items=[CredentialResponse.from_dto(item) for item in items],
        total=len(items),
        limit=limit,
        offset=offset,
    )


@router.post("/{credential_id}/resolve", response_model=ResolveCredentialResponse)
async def resolve_credential(
    credential_id: UUID,
    body: ResolveCredentialRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> ResolveCredentialResponse:
    cmd = ResolveCredentialCommand(
        tenant_id=tenant_id,
        credential_id=credential_id,
        principal_id=principal_id,
        purpose=body.purpose,
        break_glass=body.break_glass,
        justification=body.justification,
    )
    dto = await svc.resolve_credential(cmd)
    try:
        return ResolveCredentialResponse(
            credential_id=UUID(dto.credential_id),
            version_id=UUID(dto.version_id),
            secret_b64=base64.b64encode(dto.plaintext_secret).decode(),
            resolved_at=datetime.fromisoformat(dto.resolved_at),
        )
    finally:
        if isinstance(dto.plaintext_secret, bytearray):
            for i in range(len(dto.plaintext_secret)):
                dto.plaintext_secret[i] = 0


@router.patch("/{credential_id}/metadata", response_model=CredentialResponse)
async def update_metadata(
    credential_id: UUID,
    body: UpdateCredentialMetadataRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.update_metadata(
        UpdateCredentialMetadataCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            description=body.description,
            tags=body.tags if body.tags is not None else {},
        )
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/disable", response_model=CredentialResponse)
async def disable_credential(
    credential_id: UUID,
    body: DisableCredentialRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.disable_credential(
        DisableCredentialCommand(tenant_id, credential_id, principal_id, body.reason)
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/enable", response_model=CredentialResponse)
async def enable_credential(
    credential_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.enable_credential(
        EnableCredentialCommand(tenant_id, credential_id, principal_id)
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/revoke", response_model=CredentialResponse)
async def revoke_credential(
    credential_id: UUID,
    body: RevokeCredentialRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.revoke_credential(
        RevokeCredentialCommand(tenant_id, credential_id, principal_id, body.reason)
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/emergency-revoke", response_model=CredentialResponse)
async def emergency_revoke(
    credential_id: UUID,
    body: EmergencyRevokeRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.emergency_revoke(
        EmergencyRevokeCommand(
            tenant_id,
            credential_id,
            principal_id,
            body.justification,
        )
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/rotate", response_model=CredentialResponse)
async def rotate_credential(
    credential_id: UUID,
    body: RotateCredentialRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.rotate_credential(
        RotateCredentialCommand(
            tenant_id,
            credential_id,
            principal_id,
            body.new_plaintext_secret.encode("utf-8"),
            body.trigger,
            body.policy_id,
            body.notes,
        )
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/commit-rotation", response_model=CredentialResponse)
async def commit_rotation(
    credential_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.commit_rotation(CommitRotationCommand(tenant_id, credential_id, principal_id))
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/abort-rotation", response_model=CredentialResponse)
async def abort_rotation(
    credential_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.abort_rotation(
        AbortRotationCommand(tenant_id, credential_id, principal_id, "aborted via API")
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/recover", response_model=CredentialResponse)
async def recover_credential(
    credential_id: UUID,
    body: RecoverCredentialRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.recover_credential(
        RecoverCredentialCommand(
            tenant_id,
            credential_id,
            principal_id,
            body.target_version_id,
            body.justification,
        )
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/rollback-version", response_model=CredentialResponse)
async def rollback_version(
    credential_id: UUID,
    body: RollbackVersionRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.rollback_version(
        RollbackVersionCommand(tenant_id, credential_id, principal_id, body.target_version_id)
    )
    return CredentialResponse.from_dto(dto)


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def hard_delete_credential(
    credential_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> Response:
    await svc.hard_delete_credential(
        HardDeleteCredentialCommand(tenant_id, credential_id, principal_id)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{credential_id}/versions", response_model=ListVersionsResponse)
async def list_versions(
    credential_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    query_svc: CredentialQueryServiceDep,
    states: list[str] | None = Query(default=None),
) -> ListVersionsResponse:
    items = await query_svc.list_versions(
        ListVersionsQuery(tenant_id, credential_id, principal_id, states)
    )
    return ListVersionsResponse(items=[VersionResponse.from_dto(item) for item in items])


@router.get("/{credential_id}/versions/{version_id}", response_model=VersionResponse)
async def get_version(
    credential_id: UUID,
    version_id: UUID,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    query_svc: CredentialQueryServiceDep,
) -> VersionResponse:
    dto = await query_svc.get_version(
        GetVersionQuery(tenant_id, credential_id, version_id, principal_id)
    )
    return VersionResponse.from_dto(dto)


@router.post("/{credential_id}/attach-rotation-policy", response_model=CredentialResponse)
async def attach_rotation_policy(
    credential_id: UUID,
    body: AttachRotationPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.attach_rotation_policy(
        AttachRotationPolicyCommand(tenant_id, credential_id, body.policy_id, principal_id)
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/detach-rotation-policy", response_model=CredentialResponse)
async def detach_rotation_policy(
    credential_id: UUID,
    body: DetachPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.detach_rotation_policy(
        DetachRotationPolicyCommand(tenant_id, credential_id, principal_id)
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/attach-expiration-policy", response_model=CredentialResponse)
async def attach_expiration_policy(
    credential_id: UUID,
    body: AttachExpirationPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.attach_expiration_policy(
        AttachExpirationPolicyCommand(tenant_id, credential_id, body.policy_id, principal_id)
    )
    return CredentialResponse.from_dto(dto)


@router.post("/{credential_id}/detach-expiration-policy", response_model=CredentialResponse)
async def detach_expiration_policy(
    credential_id: UUID,
    body: DetachPolicyRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: CredentialServiceDep,
) -> CredentialResponse:
    dto = await svc.detach_expiration_policy(
        DetachExpirationPolicyCommand(tenant_id, credential_id, principal_id)
    )
    return CredentialResponse.from_dto(dto)
