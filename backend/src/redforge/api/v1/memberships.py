"""Organization Membership REST API endpoints.

Every mutation is scoped by the caller's verified TenantContext
(api/security.py) — organization_id is never taken from the URL/body as
a trust boundary, only as a path parameter checked against the token's
own organization via ensure_organization_match.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_membership_service
from redforge.api.security import (
    TenantContext,
    ensure_organization_match,
    require_permission,
)
from redforge.application.memberships import MembershipDTO, MembershipService
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/organizations/{organization_id}/members", tags=["memberships"])


class MembershipResponse(BaseModel):
    id: str
    user_id: str
    organization_id: str
    role: str
    status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: MembershipDTO) -> "MembershipResponse":
        return cls(
            id=dto.id, user_id=dto.user_id, organization_id=dto.organization_id,
            role=dto.role, status=dto.status,
            created_at=dto.created_at, updated_at=dto.updated_at,
        )


class ChangeRoleRequest(BaseModel):
    # "owner" is deliberately excluded — OWNER can only be granted via
    # POST .../transfer-ownership (see OwnerAssignmentNotAllowedError).
    # This is a defense-in-depth boundary check; the application layer
    # (MembershipService.change_role) enforces the same rule and is the
    # source of truth, but rejecting at the request-schema level gives
    # an immediate 422 without a service round-trip.
    role: str = Field(
        ..., pattern=r"^(admin|security_manager|analyst|member|viewer)$",
    )


class TransferOwnershipRequest(BaseModel):
    new_owner_user_id: str = Field(..., min_length=1)


@router.get("", response_model=list[MembershipResponse])
async def list_members(
    organization_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_READ)),
    service: MembershipService = Depends(get_membership_service),
) -> list[MembershipResponse]:
    """List active members of the organization."""
    ensure_organization_match(organization_id, tenant)
    dtos = await service.list_by_organization(organization_id)
    return [MembershipResponse.from_dto(d) for d in dtos]


@router.patch("/{membership_id}/role", response_model=MembershipResponse)
async def change_role(
    organization_id: str,
    membership_id: str,
    body: ChangeRoleRequest,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_MANAGE)),
    service: MembershipService = Depends(get_membership_service),
) -> MembershipResponse:
    """Change a member's role.

    Rejected with 422 if the caller targets their own membership
    (self-escalation prevention) or would leave the organization with
    no active OWNER (last-owner protection).
    """
    ensure_organization_match(organization_id, tenant)
    dto = await service.change_role(tenant.user_id, organization_id, membership_id, body.role)
    return MembershipResponse.from_dto(dto)


@router.post("/{membership_id}/suspend", response_model=MembershipResponse)
async def suspend_member(
    organization_id: str,
    membership_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_MANAGE)),
    service: MembershipService = Depends(get_membership_service),
) -> MembershipResponse:
    """Temporarily pause a member's access."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.suspend_member(tenant.user_id, organization_id, membership_id)
    return MembershipResponse.from_dto(dto)


@router.post("/{membership_id}/reactivate", response_model=MembershipResponse)
async def reactivate_member(
    organization_id: str,
    membership_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_MANAGE)),
    service: MembershipService = Depends(get_membership_service),
) -> MembershipResponse:
    """Restore a suspended member's access."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.reactivate_member(tenant.user_id, organization_id, membership_id)
    return MembershipResponse.from_dto(dto)


@router.delete("/{membership_id}", status_code=204)
async def remove_member(
    organization_id: str,
    membership_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_MANAGE)),
    service: MembershipService = Depends(get_membership_service),
) -> None:
    """Permanently remove a member from the organization."""
    ensure_organization_match(organization_id, tenant)
    await service.remove_member(tenant.user_id, organization_id, membership_id)


@router.post("/leave", status_code=204)
async def leave_organization(
    organization_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: MembershipService = Depends(get_membership_service),
) -> None:
    """Voluntarily remove your own membership.

    Gated only by ORG_READ (any active member, including VIEWER, may
    leave) rather than MEMBERS_MANAGE — leaving is self-service, not an
    administrative action on another member. Rejected with 422 if the
    caller is the organization's sole remaining OWNER.
    """
    ensure_organization_match(organization_id, tenant)
    await service.leave_organization(tenant.user_id, organization_id)


@router.post("/transfer-ownership", response_model=MembershipResponse)
async def transfer_ownership(
    organization_id: str,
    body: TransferOwnershipRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: MembershipService = Depends(get_membership_service),
) -> MembershipResponse:
    """Transfer organization ownership to another active member.

    ORG_MANAGE is held by both ADMIN and OWNER, but the service layer
    additionally requires the caller to actually hold the OWNER role —
    an ADMIN cannot transfer ownership they do not have (422, not 403,
    since this is a domain-level invariant, not a route-level
    permission gate).
    """
    ensure_organization_match(organization_id, tenant)
    dto = await service.transfer_ownership(
        tenant.user_id, organization_id, body.new_owner_user_id,
    )
    return MembershipResponse.from_dto(dto)
