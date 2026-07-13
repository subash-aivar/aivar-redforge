"""Organization Invitation REST API endpoints.

Split into two trust domains:
  - /organizations/{organization_id}/invitations/*  — organization-scoped,
    requires TenantContext (MEMBERS_INVITE/MEMBERS_MANAGE).
  - /invitations/accept, /invitations/reject         — token-authenticated,
    NOT organization-scoped (the invitee is not yet a member of anything;
    the token itself is the credential). Still requires a logged-in
    platform user (AuthenticatedPrincipal) for accept, since a Membership
    must be attached to a real User.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_invitation_service
from redforge.api.security import (
    AuthenticatedPrincipal,
    TenantContext,
    ensure_organization_match,
    get_current_principal,
    require_permission,
)
from redforge.application.invitations import InvitationDTO, InvitationService
from redforge.domain.identity.value_objects import Permission

org_scoped_router = APIRouter(
    prefix="/organizations/{organization_id}/invitations", tags=["invitations"],
)
token_router = APIRouter(prefix="/invitations", tags=["invitations"])


class CreateInvitationRequest(BaseModel):
    email: str = Field(..., min_length=5)
    # "owner" is deliberately excluded — OWNER can only be granted via
    # transfer_ownership() (see OwnerAssignmentNotAllowedError). This is
    # a defense-in-depth boundary check; the domain layer
    # (Invitation.create) enforces the same rule and is the source of
    # truth, but rejecting at the request-schema level gives an
    # immediate 422 without a service round-trip.
    role: str = Field(
        ..., pattern=r"^(admin|security_manager|analyst|member|viewer)$",
    )
    organization_name: str = Field(default="")


class InvitationResponse(BaseModel):
    id: str
    organization_id: str
    email: str
    role: str
    invited_by_user_id: str
    status: str
    expires_at: str
    accepted_by_user_id: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: InvitationDTO) -> "InvitationResponse":
        return cls(
            id=dto.id, organization_id=dto.organization_id, email=dto.email,
            role=dto.role, invited_by_user_id=dto.invited_by_user_id,
            status=dto.status, expires_at=dto.expires_at,
            accepted_by_user_id=dto.accepted_by_user_id,
            created_at=dto.created_at, updated_at=dto.updated_at,
        )


class AcceptInvitationRequest(BaseModel):
    token: str = Field(..., min_length=1)


class RejectInvitationRequest(BaseModel):
    token: str = Field(..., min_length=1)


# ─── Organization-scoped endpoints ─────────────────────────────────────────────


@org_scoped_router.post("", response_model=InvitationResponse, status_code=201)
async def create_invitation(
    organization_id: str,
    body: CreateInvitationRequest,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_INVITE)),
    service: InvitationService = Depends(get_invitation_service),
) -> InvitationResponse:
    """Invite a new member by email."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.invite(
        organization_id=organization_id,
        organization_name=body.organization_name,
        email=body.email,
        role=body.role,
        invited_by_user_id=tenant.user_id,
    )
    return InvitationResponse.from_dto(dto)


@org_scoped_router.get("", response_model=list[InvitationResponse])
async def list_invitations(
    organization_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_READ)),
    service: InvitationService = Depends(get_invitation_service),
) -> list[InvitationResponse]:
    """List invitations for the organization."""
    ensure_organization_match(organization_id, tenant)
    dtos = await service.list_by_organization(organization_id)
    return [InvitationResponse.from_dto(d) for d in dtos]


@org_scoped_router.post("/{invitation_id}/resend", response_model=InvitationResponse)
async def resend_invitation(
    organization_id: str,
    invitation_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_INVITE)),
    service: InvitationService = Depends(get_invitation_service),
) -> InvitationResponse:
    """Reissue a fresh token/expiry for a still-pending invitation."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.resend(organization_id, invitation_id, tenant.user_id)
    return InvitationResponse.from_dto(dto)


@org_scoped_router.post("/{invitation_id}/revoke", response_model=InvitationResponse)
async def revoke_invitation(
    organization_id: str,
    invitation_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.MEMBERS_MANAGE)),
    service: InvitationService = Depends(get_invitation_service),
) -> InvitationResponse:
    """Cancel a pending invitation before it is acted on."""
    ensure_organization_match(organization_id, tenant)
    dto = await service.revoke(organization_id, invitation_id, tenant.user_id)
    return InvitationResponse.from_dto(dto)


# ─── Token-authenticated endpoints (no organization membership yet) ────────────


@token_router.post("/accept", response_model=InvitationResponse)
async def accept_invitation(
    body: AcceptInvitationRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: InvitationService = Depends(get_invitation_service),
) -> InvitationResponse:
    """Accept an invitation using its token, creating a Membership for
    the currently authenticated user. Idempotent for repeated identical
    acceptance — see InvitationService.accept's docstring."""
    invitation_dto, _membership_dto = await service.accept(
        token=body.token,
        accepting_user_id=principal.user_id,
        accepting_email=principal.email,
    )
    return InvitationResponse.from_dto(invitation_dto)


@token_router.post("/reject", response_model=InvitationResponse)
async def reject_invitation(
    body: RejectInvitationRequest,
    service: InvitationService = Depends(get_invitation_service),
) -> InvitationResponse:
    """Explicitly decline an invitation using its token.

    Deliberately does NOT require authentication — an invitee should be
    able to decline without first creating a platform account, since
    accepting is the only action that requires one.
    """
    dto = await service.reject(body.token)
    return InvitationResponse.from_dto(dto)
