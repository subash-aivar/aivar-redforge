"""Platform control-plane REST API — M1 + M2.

Every endpoint here is authorized via `require_platform_permission`
(api/security.py), which resolves PlatformContext from a persisted,
live PlatformAssignment lookup — never from a JWT claim, never from
organization role. Organization admin privilege, however high, satisfies
none of these checks.

M2 adds `require_platform_permission_with_assurance` for high-impact
mutations (grant/revoke platform access, suspend/reactivate users and
organizations) — these require BOTH the platform permission AND a
current, valid step-up MFA assurance token (`X-Assurance-Token` header,
minted by `POST /platform/assurance/step-up`). A Super Admin role alone
is not enough for these.

`POST /platform/bootstrap` is the sole exception to the permission
model entirely: it requires only `get_current_principal` (any
authenticated user), because its entire purpose is to create the very
first platform assignment — there is no platform permission to require
yet. Its safety comes from PlatformAccessService.bootstrap_super_admin's
own fail-closed checks (config-gated, principal-matched, atomically
one-time), not from a permission dependency.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_assurance_service,
    get_mfa_service,
    get_platform_access_service,
    get_platform_governance_service,
    get_platform_query_service,
)
from redforge.api.security import (
    AuthenticatedPrincipal,
    PlatformContext,
    get_current_principal,
    get_platform_context,
    require_platform_permission,
    require_platform_permission_with_assurance,
)
from redforge.core.exceptions import ValidationError
from redforge.domain.identity.exceptions import UserNotFoundError
from redforge.domain.mfa.exceptions import (
    MFAAlreadyActiveError,
    MFAEnrollmentNotFoundError,
    MFAInvalidCodeError,
    MFANotActiveError,
    PrivilegedAssuranceRequiredError,
)
from redforge.domain.organizations.exceptions import OrganizationNotFoundError
from redforge.domain.platform_identity.exceptions import (
    BootstrapAlreadyConsumedError,
    BootstrapDisabledError,
    BootstrapPrincipalMismatchError,
    DuplicateActivePlatformAssignmentError,
    LastSuperAdminProtectionError,
    NonGrantablePlatformRoleError,
    PlatformAssignmentAlreadyRevokedError,
    PlatformAssignmentNotFoundError,
)
from redforge.domain.platform_identity.value_objects import (
    PlatformPermission,
    PlatformRole,
)

if TYPE_CHECKING:
    from redforge.application.mfa import MFAService, PrivilegedAssuranceService
    from redforge.application.platform_identity import (
        PlatformAccessService,
        PlatformQueryService,
    )
    from redforge.application.platform_identity.governance_service import (
        PlatformGovernanceService,
    )

router = APIRouter(prefix="/platform", tags=["platform"])


# ─── Response models ───────────────────────────────────────────────────────────


class PlatformMeResponse(BaseModel):
    user_id: str
    platform_roles: list[str]
    permissions: list[str]
    has_platform_access: bool


class BootstrapStatusResponse(BaseModel):
    available: bool


class BootstrapResponse(BaseModel):
    assignment_id: str
    role: str
    status: str


class PlatformUserResponse(BaseModel):
    id: str
    email: str
    display_name: str
    status: str
    created_at: str


class PlatformOrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    status: str
    plan: str
    created_at: str


class PlatformAssignmentResponse(BaseModel):
    id: str
    user_id: str
    role: str
    status: str
    granted_by: str
    granted_at: str
    revoked_by: str | None
    revoked_at: str | None


class GrantAccessRequest(BaseModel):
    target_user_id: str = Field(..., min_length=1)
    role: str = Field(..., description="Must be a grantable PlatformRole.")


class PlatformAuditEntryResponse(BaseModel):
    action: str
    actor_id: str
    target_id: str
    role: str | None
    outcome: str
    timestamp: str


class MFAStatusResponse(BaseModel):
    active: bool
    pending_enrollment: bool


class MFAEnrollBeginResponse(BaseModel):
    enrollment_id: str
    secret: str
    provisioning_uri: str


class MFAVerifyRequest(BaseModel):
    enrollment_id: str
    code: str = Field(..., min_length=6, max_length=8)


class StepUpRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


class StepUpResponse(BaseModel):
    assurance_token: str
    expires_at: str


class SuspendRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


# ─── Bootstrap (no platform permission required — see module docstring) ───────


@router.get("/bootstrap/status", response_model=BootstrapStatusResponse)
async def bootstrap_status(
    _: AuthenticatedPrincipal = Depends(get_current_principal),
    service: PlatformAccessService = Depends(get_platform_access_service),
) -> BootstrapStatusResponse:
    """Whether bootstrap can still be attempted. Any authenticated user
    may check this — it reveals no secret, only a boolean. The frontend
    uses this to decide whether to render a bootstrap call-to-action;
    the server remains authoritative regardless of what the UI shows.
    """
    return BootstrapStatusResponse(available=await service.bootstrap_is_available())


@router.post(
    "/bootstrap",
    response_model=BootstrapResponse,
    status_code=status.HTTP_201_CREATED,
)
async def bootstrap(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: PlatformAccessService = Depends(get_platform_access_service),
) -> BootstrapResponse:
    """One-time initial Super Admin bootstrap.

    Takes no request body — the target principal is ALWAYS the
    authenticated caller (payload.sub/email from the verified bearer
    token), never a client-supplied identity. This is what makes it
    impossible for a request to bootstrap someone else.
    """
    try:
        dto = await service.bootstrap_super_admin(
            authenticated_user_id=principal.user_id,
            authenticated_email=principal.email,
        )
    except BootstrapDisabledError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=exc.message) from exc
    except BootstrapPrincipalMismatchError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=exc.message) from exc
    except BootstrapAlreadyConsumedError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=exc.message) from exc

    return BootstrapResponse(assignment_id=dto.id, role=dto.role, status=dto.status)


# ─── Platform identity ──────────────────────────────────────────────────────────


@router.get("/me", response_model=PlatformMeResponse)
async def platform_me(
    platform: PlatformContext = Depends(get_platform_context),
) -> PlatformMeResponse:
    """Must succeed for a user with ZERO platform roles — this is how the
    frontend learns "you have no platform access." Depends on
    get_platform_context directly (not require_platform_permission, which
    would 403 first) precisely because there is no permission requirement
    to view your own — possibly empty — platform access state.
    """
    return PlatformMeResponse(
        user_id=platform.user_id,
        platform_roles=list(platform.platform_roles),
        permissions=[p.value for p in platform.permissions],
        has_platform_access=len(platform.platform_roles) > 0,
    )


# ─── MFA (self-service; any authenticated platform principal manages their
# own factor — enrollment/activation/revocation does not require an existing
# platform permission, since a brand-new Super Admin has no MFA yet) ───────────


@router.get("/mfa/status", response_model=MFAStatusResponse)
async def mfa_status(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> MFAStatusResponse:
    dto = await mfa_service.get_status(principal.user_id)
    return MFAStatusResponse(active=dto.active, pending_enrollment=dto.pending_enrollment)


@router.post(
    "/mfa/enroll/begin",
    response_model=MFAEnrollBeginResponse,
    status_code=status.HTTP_201_CREATED,
)
async def mfa_enroll_begin(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> MFAEnrollBeginResponse:
    """Begins TOTP enrollment. The plaintext secret and provisioning URI
    are returned in THIS response ONLY — never again, by any endpoint,
    to any caller, even the same user. The frontend must render/discard
    them immediately and never persist them client-side beyond the
    enrollment ceremony.
    """
    try:
        result = await mfa_service.begin_enrollment(principal.user_id, principal.email)
    except MFAAlreadyActiveError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=exc.message) from exc
    return MFAEnrollBeginResponse(
        enrollment_id=result.enrollment_id,
        secret=result.secret,
        provisioning_uri=result.provisioning_uri,
    )


@router.post("/mfa/enroll/verify", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_enroll_verify(
    body: MFAVerifyRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> None:
    """Proof of possession: activates the pending factor only if the
    submitted TOTP code verifies against it."""
    try:
        await mfa_service.verify_and_activate(principal.user_id, body.enrollment_id, body.code)
    except MFAEnrollmentNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    except MFAInvalidCodeError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.message) from exc


@router.post("/mfa/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_revoke(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> None:
    """Revoke your own active MFA factor. Does not require step-up
    assurance itself (you cannot be locked out of un-enrolling), but a
    revoked factor immediately stops being able to satisfy any future
    step-up request — including one already in flight, since assurance
    validation and factor status are both read live, never cached.
    """
    try:
        await mfa_service.revoke(principal.user_id, actor_id=principal.user_id)
    except MFANotActiveError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=exc.message) from exc


# ─── Privileged assurance (step-up) ────────────────────────────────────────────


@router.post("/assurance/step-up", response_model=StepUpResponse)
async def step_up(
    body: StepUpRequest,
    platform: PlatformContext = Depends(get_platform_context),
    assurance_service: PrivilegedAssuranceService = Depends(get_assurance_service),
) -> StepUpResponse:
    """Verify a current TOTP code against the caller's ACTIVE MFA factor
    and mint a short-lived assurance token. Requires platform context
    (i.e. the caller holds SOME platform role) but not any specific
    permission — you can only step up into permissions you already have.
    """
    try:
        result = await assurance_service.establish(platform.user_id, body.code)
    except PrivilegedAssuranceRequiredError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=exc.message) from exc
    return StepUpResponse(
        assurance_token=result.assurance_token, expires_at=result.expires_at,
    )


# ─── Platform user / organization visibility ───────────────────────────────────


@router.get("/users", response_model=list[PlatformUserResponse])
async def list_platform_users(
    limit: int = 50,
    offset: int = 0,
    _: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_USERS_READ)
    ),
    query_service: PlatformQueryService = Depends(get_platform_query_service),
) -> list[PlatformUserResponse]:
    users = await query_service.list_users(limit=limit, offset=offset)
    return [PlatformUserResponse(**dataclasses.asdict(u)) for u in users]


@router.get("/users/{user_id}", response_model=PlatformUserResponse)
async def get_platform_user(
    user_id: str,
    _: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_USERS_READ)
    ),
    governance_service: PlatformGovernanceService = Depends(get_platform_governance_service),
) -> PlatformUserResponse:
    try:
        dto = await governance_service.get_user_detail(user_id)
    except UserNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return PlatformUserResponse(**dataclasses.asdict(dto))


@router.post("/users/{user_id}/suspend", response_model=PlatformUserResponse)
async def suspend_platform_user(
    user_id: str,
    body: SuspendRequest,
    platform: PlatformContext = Depends(
        require_platform_permission_with_assurance(PlatformPermission.PLATFORM_USERS_SUSPEND)
    ),
    governance_service: PlatformGovernanceService = Depends(get_platform_governance_service),
) -> PlatformUserResponse:
    try:
        dto = await governance_service.suspend_user(user_id, platform.user_id, body.reason)
    except UserNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.message) from exc
    return PlatformUserResponse(**dataclasses.asdict(dto))


@router.post("/users/{user_id}/reactivate", response_model=PlatformUserResponse)
async def reactivate_platform_user(
    user_id: str,
    platform: PlatformContext = Depends(
        require_platform_permission_with_assurance(PlatformPermission.PLATFORM_USERS_REACTIVATE)
    ),
    governance_service: PlatformGovernanceService = Depends(get_platform_governance_service),
) -> PlatformUserResponse:
    try:
        dto = await governance_service.reactivate_user(user_id, platform.user_id)
    except UserNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return PlatformUserResponse(**dataclasses.asdict(dto))


@router.get("/organizations", response_model=list[PlatformOrganizationResponse])
async def list_platform_organizations(
    limit: int = 50,
    offset: int = 0,
    _: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_ORGANIZATIONS_READ)
    ),
    query_service: PlatformQueryService = Depends(get_platform_query_service),
) -> list[PlatformOrganizationResponse]:
    orgs = await query_service.list_organizations(limit=limit, offset=offset)
    return [PlatformOrganizationResponse(**dataclasses.asdict(o)) for o in orgs]


@router.post("/organizations/{organization_id}/suspend", status_code=status.HTTP_204_NO_CONTENT)
async def suspend_platform_organization(
    organization_id: str,
    body: SuspendRequest,
    platform: PlatformContext = Depends(
        require_platform_permission_with_assurance(
            PlatformPermission.PLATFORM_ORGANIZATIONS_SUSPEND
        )
    ),
    governance_service: PlatformGovernanceService = Depends(get_platform_governance_service),
) -> None:
    """Platform governance suspension — NOT tenant impersonation. This
    reuses the organization's existing suspend() lifecycle (the same one
    org self-service uses), which already denies tenant-scoped requests
    live (require_permission checks org.status on every request), so a
    previously-issued org-scoped token is denied immediately, not after
    expiry.
    """
    try:
        await governance_service.suspend_organization(
            organization_id, platform.user_id, body.reason,
        )
    except OrganizationNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc


@router.post(
    "/organizations/{organization_id}/reactivate", status_code=status.HTTP_204_NO_CONTENT,
)
async def reactivate_platform_organization(
    organization_id: str,
    platform: PlatformContext = Depends(
        require_platform_permission_with_assurance(
            PlatformPermission.PLATFORM_ORGANIZATIONS_REACTIVATE
        )
    ),
    governance_service: PlatformGovernanceService = Depends(get_platform_governance_service),
) -> None:
    try:
        await governance_service.reactivate_organization(organization_id, platform.user_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc


# ─── Platform access governance ─────────────────────────────────────────────────


@router.get("/access", response_model=list[PlatformAssignmentResponse])
async def list_platform_access(
    limit: int = 50,
    offset: int = 0,
    _: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_ACCESS_READ)
    ),
    service: PlatformAccessService = Depends(get_platform_access_service),
) -> list[PlatformAssignmentResponse]:
    assignments = await service.list_assignments(limit=limit, offset=offset)
    return [PlatformAssignmentResponse(**dataclasses.asdict(a)) for a in assignments]


@router.post(
    "/access",
    response_model=PlatformAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def grant_platform_access(
    body: GrantAccessRequest,
    platform: PlatformContext = Depends(
        require_platform_permission_with_assurance(PlatformPermission.PLATFORM_ACCESS_GRANT)
    ),
    service: PlatformAccessService = Depends(get_platform_access_service),
) -> PlatformAssignmentResponse:
    try:
        role = PlatformRole(body.role)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unknown platform role: {body.role!r}"
        ) from exc

    try:
        dto = await service.grant(
            target_user_id=body.target_user_id, role=role, granted_by=platform.user_id
        )
    except NonGrantablePlatformRoleError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.message) from exc
    except DuplicateActivePlatformAssignmentError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=exc.message) from exc

    return PlatformAssignmentResponse(**dataclasses.asdict(dto))


@router.post("/access/{assignment_id}/revoke", response_model=PlatformAssignmentResponse)
async def revoke_platform_access(
    assignment_id: str,
    platform: PlatformContext = Depends(
        require_platform_permission_with_assurance(PlatformPermission.PLATFORM_ACCESS_REVOKE)
    ),
    service: PlatformAccessService = Depends(get_platform_access_service),
) -> PlatformAssignmentResponse:
    try:
        dto = await service.revoke(assignment_id, revoked_by=platform.user_id)
    except PlatformAssignmentNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    except PlatformAssignmentAlreadyRevokedError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=exc.message) from exc
    except LastSuperAdminProtectionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=exc.message) from exc

    return PlatformAssignmentResponse(**dataclasses.asdict(dto))


# ─── Platform security audit ────────────────────────────────────────────────────


@router.get("/audit", response_model=list[PlatformAuditEntryResponse])
async def get_platform_audit(
    limit: int = 100,
    _: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_AUDIT_READ)
    ),
    service: PlatformAccessService = Depends(get_platform_access_service),
) -> list[PlatformAuditEntryResponse]:
    entries = await service.query_audit(limit=limit)
    return [
        PlatformAuditEntryResponse(
            action=e.action.value,
            actor_id=e.actor_id,
            target_id=e.resource_id,
            role=e.metadata.get("role"),
            outcome=str(e.metadata.get("outcome", "")),
            timestamp=e.timestamp.isoformat(),
        )
        for e in entries
    ]
