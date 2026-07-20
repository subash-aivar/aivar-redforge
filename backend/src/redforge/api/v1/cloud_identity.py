"""M26 Phase 3 internal APIs — cloud IAM identity discovery and queries."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_identity_discovery_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.identity_dtos import (
    GetIAMPrincipalQuery,
    ListAttachedPoliciesQuery,
    ListIAMPrincipalsQuery,
    ListTrustRelationshipsQuery,
    TriggerIdentityDiscoveryCommand,
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.identity_discovery_service import (
        IdentityDiscoveryService,
    )

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class IdentityDiscoveryResultResponse(BaseModel):
    cloud_account_id: UUID
    organization_id: str
    sync_status: str
    discovered_count: int
    updated_count: int
    resurrected_count: int
    deleted_count: int
    projected_count: int


class PolicyAttachmentResponse(BaseModel):
    attachment_id: str
    policy_provider_id: str
    policy_name: str
    attachment_type: str
    is_inline: bool


class TrustRelationshipResponse(BaseModel):
    trust_id: str
    trusted_principal_provider_id: str
    trust_type: str
    is_cross_account: bool
    conditions: list[list[str]] = Field(default_factory=list)


class CloudIAMPrincipalResponse(BaseModel):
    principal_id: UUID
    cloud_account_id: UUID
    organization_id: str
    principal_type: str
    provider_id: str
    display_name: str
    privilege_level: str
    is_federated: bool
    is_human: bool
    is_disabled: bool
    is_deleted: bool
    last_activity_at: str | None
    last_seen_at: str
    first_seen_at: str
    created_at: str
    updated_at: str
    version: int
    attached_policies: list[PolicyAttachmentResponse] = Field(default_factory=list)
    trust_relationships: list[TrustRelationshipResponse] = Field(default_factory=list)


class CloudIAMPrincipalPageResponse(BaseModel):
    items: list[CloudIAMPrincipalResponse]
    page: int
    size: int
    total: int


def _policy_response(dto: object) -> PolicyAttachmentResponse:
    return PolicyAttachmentResponse(
        attachment_id=str(dto.attachment_id),  # type: ignore[attr-defined]
        policy_provider_id=str(dto.policy_provider_id),  # type: ignore[attr-defined]
        policy_name=str(dto.policy_name),  # type: ignore[attr-defined]
        attachment_type=str(dto.attachment_type),  # type: ignore[attr-defined]
        is_inline=bool(dto.is_inline),  # type: ignore[attr-defined]
    )


def _trust_response(dto: object) -> TrustRelationshipResponse:
    return TrustRelationshipResponse(
        trust_id=str(dto.trust_id),  # type: ignore[attr-defined]
        trusted_principal_provider_id=str(dto.trusted_principal_provider_id),  # type: ignore[attr-defined]
        trust_type=str(dto.trust_type),  # type: ignore[attr-defined]
        is_cross_account=bool(dto.is_cross_account),  # type: ignore[attr-defined]
        conditions=[list(pair) for pair in (dto.conditions or [])],  # type: ignore[attr-defined]
    )


def _principal_response(dto: object) -> CloudIAMPrincipalResponse:
    last_activity = getattr(dto, "last_activity_at", None)
    return CloudIAMPrincipalResponse(
        principal_id=UUID(str(dto.principal_id)),  # type: ignore[attr-defined]
        cloud_account_id=UUID(str(dto.cloud_account_id)),  # type: ignore[attr-defined]
        organization_id=str(dto.organization_id),  # type: ignore[attr-defined]
        principal_type=str(dto.principal_type),  # type: ignore[attr-defined]
        provider_id=str(dto.provider_id),  # type: ignore[attr-defined]
        display_name=str(dto.display_name),  # type: ignore[attr-defined]
        privilege_level=str(dto.privilege_level),  # type: ignore[attr-defined]
        is_federated=bool(dto.is_federated),  # type: ignore[attr-defined]
        is_human=bool(dto.is_human),  # type: ignore[attr-defined]
        is_disabled=bool(dto.is_disabled),  # type: ignore[attr-defined]
        is_deleted=bool(dto.is_deleted),  # type: ignore[attr-defined]
        last_activity_at=last_activity.isoformat() if last_activity is not None else None,
        last_seen_at=dto.last_seen_at.isoformat(),  # type: ignore[attr-defined]
        first_seen_at=dto.first_seen_at.isoformat(),  # type: ignore[attr-defined]
        created_at=dto.created_at.isoformat(),  # type: ignore[attr-defined]
        updated_at=dto.updated_at.isoformat(),  # type: ignore[attr-defined]
        version=int(dto.version),  # type: ignore[attr-defined]
        attached_policies=[_policy_response(p) for p in dto.attached_policies],  # type: ignore[attr-defined]
        trust_relationships=[_trust_response(t) for t in dto.trust_relationships],  # type: ignore[attr-defined]
    )


@router.post(
    "/accounts/{account_id}/discover-identity",
    status_code=status.HTTP_200_OK,
    response_model=IdentityDiscoveryResultResponse,
)
async def trigger_identity_discovery(
    account_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: IdentityDiscoveryService = Depends(get_identity_discovery_service),
) -> IdentityDiscoveryResultResponse:
    dto = await service.discover_account(
        TriggerIdentityDiscoveryCommand(
            organization_id=tenant.organization_id,
            cloud_account_id=str(account_id),
        )
    )
    return IdentityDiscoveryResultResponse(
        cloud_account_id=UUID(dto.cloud_account_id),
        organization_id=dto.organization_id,
        sync_status=dto.sync_status,
        discovered_count=dto.discovered_count,
        updated_count=dto.updated_count,
        resurrected_count=dto.resurrected_count,
        deleted_count=dto.deleted_count,
        projected_count=dto.projected_count,
    )


@router.get("/iam/principals", response_model=CloudIAMPrincipalPageResponse)
async def list_iam_principals(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: IdentityDiscoveryService = Depends(get_identity_discovery_service),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
    cloud_account_id: UUID | None = None,
    principal_type: str | None = None,
    include_deleted: bool = Query(default=False),
) -> CloudIAMPrincipalPageResponse:
    result = await service.list_principals(
        ListIAMPrincipalsQuery(
            organization_id=tenant.organization_id,
            page=page,
            size=size,
            cloud_account_id=str(cloud_account_id) if cloud_account_id else None,
            principal_type=principal_type,
            include_deleted=include_deleted,
        )
    )
    return CloudIAMPrincipalPageResponse(
        items=[_principal_response(item) for item in result.items],
        page=result.page,
        size=result.size,
        total=result.total,
    )


@router.get("/iam/principals/{principal_id}", response_model=CloudIAMPrincipalResponse)
async def get_iam_principal(
    principal_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: IdentityDiscoveryService = Depends(get_identity_discovery_service),
) -> CloudIAMPrincipalResponse:
    dto = await service.get_principal(
        GetIAMPrincipalQuery(
            organization_id=tenant.organization_id,
            principal_id=str(principal_id),
        )
    )
    return _principal_response(dto)


@router.get(
    "/iam/principals/{principal_id}/policies",
    response_model=list[PolicyAttachmentResponse],
)
async def list_principal_policies(
    principal_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: IdentityDiscoveryService = Depends(get_identity_discovery_service),
) -> list[PolicyAttachmentResponse]:
    items = await service.list_attached_policies(
        ListAttachedPoliciesQuery(
            organization_id=tenant.organization_id,
            principal_id=str(principal_id),
        )
    )
    return [_policy_response(item) for item in items]


@router.get(
    "/iam/principals/{principal_id}/trusts",
    response_model=list[TrustRelationshipResponse],
)
async def list_principal_trusts(
    principal_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: IdentityDiscoveryService = Depends(get_identity_discovery_service),
) -> list[TrustRelationshipResponse]:
    items = await service.list_trust_relationships(
        ListTrustRelationshipsQuery(
            organization_id=tenant.organization_id,
            principal_id=str(principal_id),
        )
    )
    return [_trust_response(item) for item in items]
