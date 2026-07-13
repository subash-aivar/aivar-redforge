"""Centralized authentication and authorization for the API layer.

This module is the single source of truth for:
  - Extracting and validating the bearer token -> AuthenticatedPrincipal
  - Resolving verified organization context from the token -> TenantContext
  - Enforcing RBAC permissions using the EXISTING domain model
    (MembershipRole / Permission / ROLE_PERMISSIONS from
    domain.identity.value_objects) — no second authorization model.

Every organization-scoped router depends on `require_permission(...)`
from this module. No router performs its own token parsing or ad hoc
permission checks — that consistency is the point.

Tenant isolation design: organization_id is NEVER read from client
request data. TenantContext.organization_id comes only from a signed,
server-issued access token's `org` claim, which is populated only by
POST /auth/organizations/{organization_id}/select — an endpoint that
independently verifies an active Membership row exists before minting
that token. A client cannot forge or widen its own organization scope:
JWT signature verification means `org`/`role` here are exactly what the
server decided at select-time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from redforge.api.dependencies import (
    get_organization_service,
    get_platform_access_service,
    get_token_service,
    get_user_status_service,
)
from redforge.core.exceptions import AuthenticationError, AuthorizationError
from redforge.domain.identity.value_objects import (
    ROLE_PERMISSIONS,
    MembershipRole,
    Permission,
)
from redforge.domain.organizations.exceptions import OrganizationInactiveError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from redforge.application.auth import UserStatusService
    from redforge.application.mfa import PrivilegedAssuranceService
    from redforge.application.organizations import OrganizationService
    from redforge.application.platform_identity import PlatformAccessService
    from redforge.domain.platform_identity.value_objects import PlatformPermission
    from redforge.infrastructure.auth.contracts import TokenPayload, TokenService

_bearer_scheme = HTTPBearer(
    scheme_name="BearerAuth",
    description="RedForge access token, obtained from POST /auth/login or /auth/register.",
    auto_error=False,
)


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """A verified caller identity with no organization context.

    Used only by endpoints that operate before/outside any specific
    organization (e.g. "create an organization," "list my memberships").
    Every other endpoint should depend on TenantContext instead.
    """

    user_id: str
    email: str


@dataclass(frozen=True, slots=True)
class TenantContext:
    """A verified caller identity acting within one membership-checked
    organization. This is the ONLY source of organization_id that
    application/repository code should ever trust.
    """

    user_id: str
    email: str
    organization_id: str
    role: MembershipRole
    permissions: frozenset[Permission]

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions


async def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    token_service: TokenService = Depends(get_token_service),
    user_status_service: UserStatusService = Depends(get_user_status_service),
) -> AuthenticatedPrincipal:
    """Require a valid access token. Does not require organization context.

    Also re-checks the account's LIVE status (M2) — a signed, unexpired
    token only proves the user authenticated successfully at issuance
    time; it says nothing about whether the account is still in good
    standing now. Without this check, suspending a user via the platform
    governance API would have no effect until their token happened to
    expire — the exact gap `require_permission`'s live organization-
    suspension check already closed for organizations.
    """
    payload = _decode_or_raise(credentials, token_service)
    await _ensure_user_active(payload.sub, user_status_service)
    return AuthenticatedPrincipal(user_id=payload.sub, email=payload.email)


async def get_tenant_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    token_service: TokenService = Depends(get_token_service),
    user_status_service: UserStatusService = Depends(get_user_status_service),
) -> TenantContext:
    """Require a valid access token that also carries a selected
    organization (see module docstring for how that claim is minted).
    """
    payload = _decode_or_raise(credentials, token_service)
    await _ensure_user_active(payload.sub, user_status_service)

    if not payload.organization_id or not payload.role:
        raise AuthorizationError(
            "No organization selected for this session. Call "
            "POST /auth/organizations/{organization_id}/select first."
        )
    try:
        role = MembershipRole(payload.role)
    except ValueError as exc:
        raise AuthenticationError("Token carries an unrecognized role") from exc

    return TenantContext(
        user_id=payload.sub,
        email=payload.email,
        organization_id=payload.organization_id,
        role=role,
        permissions=ROLE_PERMISSIONS[role],
    )


@dataclass(frozen=True, slots=True)
class PlatformContext:
    """A verified caller identity acting with PLATFORM-wide authorization —
    entirely distinct from TenantContext.

    Deliberately structurally different from TenantContext (no shared base
    class, no overlapping optional fields) so a function that requires one
    cannot accidentally accept the other via duck typing: TenantContext has
    `organization_id`/`role: MembershipRole`, PlatformContext has neither.
    A FastAPI route parameter typed `PlatformContext` can only be satisfied
    by `get_platform_context`, and vice versa for `TenantContext` — there is
    no code path where an organization-scoped dependency graph produces a
    PlatformContext or where a platform-scoped one produces a TenantContext.

    PlatformContext intentionally holds ONLY authenticated platform
    authorization state: user_id, email, and effective platform
    permissions. It must never carry organization_id, target_id,
    campaign_id, or any other request-scoped/tenant-scoped identifier —
    those never belong in a platform authorization object precisely
    because platform authorization must never imply tenant data access.
    """

    user_id: str
    email: str
    platform_roles: tuple[str, ...]
    permissions: frozenset[PlatformPermission]

    def has_permission(self, permission: PlatformPermission) -> bool:
        return permission in self.permissions


async def get_platform_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    token_service: TokenService = Depends(get_token_service),
    platform_access_service: PlatformAccessService = Depends(get_platform_access_service),
    user_status_service: UserStatusService = Depends(get_user_status_service),
) -> PlatformContext:
    """Resolve PlatformContext from an authenticated principal ONLY.

    Critically, this does NOT read the token's `org`/`role` claims at
    all — platform authorization is looked up fresh from persisted
    PlatformAssignment rows on every call (see PlatformAccessService),
    so it is impossible for organization-scoped JWT claims to influence
    platform authorization, and a revoked platform assignment takes
    effect on the very next request with no token refresh needed.
    """
    payload = _decode_or_raise(credentials, token_service)
    await _ensure_user_active(payload.sub, user_status_service)
    access = await platform_access_service.get_access_for_user(payload.sub)
    return PlatformContext(
        user_id=payload.sub,
        email=payload.email,
        platform_roles=access.roles,
        permissions=access.permissions,
    )


def require_platform_permission(
    permission: PlatformPermission,
) -> Callable[..., Awaitable[PlatformContext]]:
    """Dependency factory enforcing a single PlatformPermission.

    Mirrors require_permission's shape for the tenant control plane, but
    is entirely independent of it: it never touches TenantContext,
    MembershipRole, or organization_id, and organization admin privilege
    (however high) satisfies none of these checks — only a persisted,
    ACTIVE PlatformAssignment does.
    """

    async def _dependency(
        platform: PlatformContext = Depends(get_platform_context),
    ) -> PlatformContext:
        if not platform.has_permission(permission):
            raise AuthorizationError(
                f"Missing required platform permission '{permission.value}'"
            )
        return platform

    return _dependency


def require_platform_permission_with_assurance(
    permission: PlatformPermission,
) -> Callable[..., Awaitable[PlatformContext]]:
    """Like require_platform_permission, but additionally requires a
    current, valid step-up MFA assurance token (`X-Assurance-Token`
    header) — for high-impact mutations (grant/revoke platform access,
    suspend/reactivate users/organizations). A Super Admin's permission
    alone is not enough for these; they must have proven MFA recently
    (within Settings.platform_assurance_ttl_seconds).

    Distinguishes "wrong/missing permission" (AuthorizationError, 403,
    generic) from "right permission but no current MFA proof"
    (PrivilegedAssuranceRequiredError, 403, MFA_ASSURANCE_REQUIRED) so
    the frontend can route the latter into the step-up flow rather than
    a dead end.
    """
    from fastapi import Header

    from redforge.api.dependencies import get_assurance_service
    from redforge.domain.mfa.exceptions import PrivilegedAssuranceRequiredError

    async def _dependency(
        platform: PlatformContext = Depends(get_platform_context),
        assurance_service: PrivilegedAssuranceService = Depends(get_assurance_service),
        x_assurance_token: str | None = Header(default=None),
    ) -> PlatformContext:
        if not platform.has_permission(permission):
            raise AuthorizationError(
                f"Missing required platform permission '{permission.value}'"
            )
        valid = await assurance_service.validate(platform.user_id, x_assurance_token)
        if not valid:
            raise PrivilegedAssuranceRequiredError
        return platform

    return _dependency


def require_permission(
    permission: Permission,
    *,
    allow_when_suspended: bool = False,
) -> Callable[..., Awaitable[TenantContext]]:
    """Dependency factory enforcing a single Permission.

    This is also the single, central enforcement point for "operationally
    suspended" organizations: since virtually every organization-scoped
    route in the platform (memberships, invitations, targets, validations,
    findings, evidence, policies, risk incidents, organization
    administration itself) depends on this function, checking suspension
    here — once — covers all of them without a single duplicated check
    in any application service. A suspended organization's live status is
    read fresh on every request (not cached in the JWT), so suspension
    takes effect immediately for already-issued tokens, not just future
    logins.

    A caller with `allow_when_suspended=True` opts a specific route out —
    used only for the operations that must keep working on a suspended
    organization: viewing it (GET), suspending it again (idempotent), and
    reactivating it (POST .../activate). Every other organization-scoped
    route defaults to being blocked while suspended. Deactivated
    (INACTIVE) organizations are unaffected by this check — this sprint's
    remediation is scoped to SUSPENDED specifically, per the reported
    finding.

    Usage:
        @router.get("/findings")
        async def list_findings(
            tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
        ) -> ...:
            # tenant.organization_id is verified — safe to scope queries with it.
    """

    async def _dependency(
        tenant: TenantContext = Depends(get_tenant_context),
        org_service: OrganizationService = Depends(get_organization_service),
    ) -> TenantContext:
        if not tenant.has_permission(permission):
            raise AuthorizationError(
                f"Role '{tenant.role.value}' lacks required permission "
                f"'{permission.value}'"
            )
        if not allow_when_suspended:
            org = await org_service.get_by_id(tenant.organization_id)
            if org.status == "suspended":
                raise OrganizationInactiveError(tenant.organization_id)
        return tenant

    return _dependency


def ensure_organization_match(path_organization_id: str, tenant: TenantContext) -> None:
    """Guard for routes where organization_id also appears as a path
    parameter (e.g. GET /organizations/{organization_id}).

    A caller's token scopes them to exactly one organization; this
    rejects any attempt to address a *different* organization via the
    URL even though the caller holds a validly-signed token — the token
    proves membership in tenant.organization_id, not in whatever ID
    happens to be in the path.
    """
    if path_organization_id != tenant.organization_id:
        raise AuthorizationError(
            "Token is not scoped to the requested organization"
        )


def _decode_or_raise(
    credentials: HTTPAuthorizationCredentials | None,
    token_service: TokenService,
) -> TokenPayload:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Missing bearer token")
    payload = token_service.decode_access_token(credentials.credentials)
    if payload is None:
        raise AuthenticationError("Invalid or expired access token")
    return payload


async def _ensure_user_active(user_id: str, user_status_service: UserStatusService) -> None:
    """M2: re-check the account's live status on every authenticated
    request. A missing user (deleted) or any status other than ACTIVE
    (SUSPENDED, INACTIVE, PENDING) denies access immediately — this is
    what makes user suspension effective against already-issued tokens
    without waiting for expiry.
    """
    status = await user_status_service.get_status(user_id)
    if status != "active":
        raise AuthenticationError("Account is not active")
