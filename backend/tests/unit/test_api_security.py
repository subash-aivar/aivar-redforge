"""Unit tests for the centralized API auth/authz dependencies (api/security.py).

Tests the dependency functions directly, isolated from FastAPI routing —
complements the end-to-end API integration tests in tests/api/.
"""

from __future__ import annotations

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from redforge.api.security import (
    AuthenticatedPrincipal,
    TenantContext,
    ensure_organization_match,
    get_current_principal,
    get_tenant_context,
    require_permission,
)
from redforge.application.organizations import OrganizationDTO
from redforge.core.exceptions import AuthenticationError, AuthorizationError
from redforge.domain.identity.value_objects import (
    ROLE_PERMISSIONS,
    MembershipRole,
    Permission,
)
from redforge.domain.organizations.exceptions import OrganizationInactiveError
from redforge.infrastructure.auth.contracts import TokenPayload


class _FakeOrganizationService:
    """A minimal OrganizationService double — returns a fixed status
    without touching a database, so require_permission's suspension
    check can be unit-tested in isolation."""

    def __init__(self, status: str = "active") -> None:
        self._status = status

    async def get_by_id(self, organization_id: str) -> OrganizationDTO:
        return OrganizationDTO(
            id=organization_id,
            name="Test Org",
            slug="test-org",
            status=self._status,
            plan="free",
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        )


def _active_org() -> _FakeOrganizationService:
    return _FakeOrganizationService("active")


class _FakeTokenService:
    """A minimal TokenService double the tests control directly."""

    def __init__(self, payload: TokenPayload | None) -> None:
        self._payload = payload

    def create_tokens(self, payload: TokenPayload) -> object:  # pragma: no cover
        raise NotImplementedError

    def decode_access_token(self, token: str) -> TokenPayload | None:
        return self._payload

    def decode_refresh_token(self, token: str) -> TokenPayload | None:  # pragma: no cover
        raise NotImplementedError


def _credentials(token: str = "irrelevant-since-fake-service") -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class _FakeActiveUserStatusService:
    """Every user is ACTIVE — suspension-specific behavior is covered by
    tests/api/test_platform_identity_api.py's live suspension tests."""

    async def get_status(self, user_id: str) -> str:
        return "active"


class TestGetCurrentPrincipal:
    async def test_valid_token_returns_principal(self) -> None:
        payload = TokenPayload(sub="user-1", email="a@test.com")
        principal = await get_current_principal(
            credentials=_credentials(),
            token_service=_FakeTokenService(payload),
            user_status_service=_FakeActiveUserStatusService(),
        )
        assert isinstance(principal, AuthenticatedPrincipal)
        assert principal.user_id == "user-1"
        assert principal.email == "a@test.com"

    async def test_missing_credentials_raises_authentication_error(self) -> None:
        with pytest.raises(AuthenticationError):
            await get_current_principal(
                credentials=None,
                token_service=_FakeTokenService(None),
                user_status_service=_FakeActiveUserStatusService(),
            )

    async def test_invalid_token_raises_authentication_error(self) -> None:
        with pytest.raises(AuthenticationError):
            await get_current_principal(
                credentials=_credentials(),
                token_service=_FakeTokenService(None),
                user_status_service=_FakeActiveUserStatusService(),
            )

    async def test_empty_credentials_string_raises(self) -> None:
        with pytest.raises(AuthenticationError):
            await get_current_principal(
                credentials=_credentials(""),
                token_service=_FakeTokenService(None),
                user_status_service=_FakeActiveUserStatusService(),
            )


class TestGetTenantContext:
    async def test_scoped_token_returns_tenant_context(self) -> None:
        payload = TokenPayload(
            sub="user-1",
            email="a@test.com",
            organization_id="org-1",
            role="admin",
        )
        tenant = await get_tenant_context(
            credentials=_credentials(),
            token_service=_FakeTokenService(payload),
            user_status_service=_FakeActiveUserStatusService(),
        )
        assert isinstance(tenant, TenantContext)
        assert tenant.organization_id == "org-1"
        assert tenant.role == MembershipRole.ADMIN
        assert tenant.permissions == ROLE_PERMISSIONS[MembershipRole.ADMIN]

    async def test_unscoped_token_raises_authorization_error(self) -> None:
        """A valid token with no organization/role claim (i.e. never
        went through /auth/organizations/{id}/select) must be rejected —
        it proves identity, not tenant membership."""
        payload = TokenPayload(sub="user-1", email="a@test.com")
        with pytest.raises(AuthorizationError):
            await get_tenant_context(
                credentials=_credentials(),
                token_service=_FakeTokenService(payload),
                user_status_service=_FakeActiveUserStatusService(),
            )

    async def test_partial_claims_raises_authorization_error(self) -> None:
        """org claim present but role missing (or vice versa) must not
        silently degrade — treated the same as unscoped."""
        payload = TokenPayload(
            sub="user-1",
            email="a@test.com",
            organization_id="org-1",
            role=None,
        )
        with pytest.raises(AuthorizationError):
            await get_tenant_context(
                credentials=_credentials(),
                token_service=_FakeTokenService(payload),
                user_status_service=_FakeActiveUserStatusService(),
            )

    async def test_unrecognized_role_raises_authentication_error(self) -> None:
        payload = TokenPayload(
            sub="user-1",
            email="a@test.com",
            organization_id="org-1",
            role="super_admin_backdoor",
        )
        with pytest.raises(AuthenticationError):
            await get_tenant_context(
                credentials=_credentials(),
                token_service=_FakeTokenService(payload),
                user_status_service=_FakeActiveUserStatusService(),
            )

    async def test_missing_token_raises_authentication_before_authorization(self) -> None:
        """No credentials at all is an authentication failure (401), not
        an authorization failure (403) — must fail before the org-scope
        check even runs."""
        with pytest.raises(AuthenticationError):
            await get_tenant_context(
                credentials=None,
                token_service=_FakeTokenService(None),
                user_status_service=_FakeActiveUserStatusService(),
            )


class TestRequirePermission:
    def _tenant(self, role: MembershipRole) -> TenantContext:
        return TenantContext(
            user_id="u",
            email="e@test.com",
            organization_id="org-1",
            role=role,
            permissions=ROLE_PERMISSIONS[role],
        )

    async def test_role_with_permission_passes(self) -> None:
        dependency = require_permission(Permission.FINDINGS_READ)
        tenant = self._tenant(MembershipRole.VIEWER)
        result = await dependency(tenant=tenant, org_service=_active_org())
        assert result is tenant

    async def test_role_without_permission_raises(self) -> None:
        dependency = require_permission(Permission.MEMBERS_MANAGE)
        tenant = self._tenant(MembershipRole.VIEWER)
        with pytest.raises(AuthorizationError):
            await dependency(tenant=tenant, org_service=_active_org())

    async def test_owner_has_every_permission(self) -> None:
        tenant = self._tenant(MembershipRole.OWNER)
        for permission in Permission:
            dependency = require_permission(permission)
            result = await dependency(tenant=tenant, org_service=_active_org())
            assert result is tenant

    @pytest.mark.parametrize(
        "role,permission,allowed",
        [
            (MembershipRole.MEMBER, Permission.VALIDATIONS_RUN, True),
            (MembershipRole.MEMBER, Permission.MEMBERS_MANAGE, False),
            (MembershipRole.MEMBER, Permission.VALIDATIONS_MANAGE, False),
            (MembershipRole.ADMIN, Permission.VALIDATIONS_MANAGE, True),
            (MembershipRole.ADMIN, Permission.ORG_MANAGE, True),
            (MembershipRole.VIEWER, Permission.FINDINGS_READ, True),
            (MembershipRole.VIEWER, Permission.TARGETS_CREATE, False),
            (MembershipRole.VIEWER, Permission.VALIDATIONS_RUN, False),
        ],
    )
    async def test_role_permission_matrix(
        self,
        role: MembershipRole,
        permission: Permission,
        allowed: bool,
    ) -> None:
        dependency = require_permission(permission)
        tenant = self._tenant(role)
        if allowed:
            assert await dependency(tenant=tenant, org_service=_active_org()) is tenant
        else:
            with pytest.raises(AuthorizationError):
                await dependency(tenant=tenant, org_service=_active_org())


class TestRequirePermissionSuspension:
    """The centralized 'operationally suspended' enforcement point — see
    require_permission's docstring. One dependency, checked by every
    organization-scoped route, covers all of them without per-service
    duplication."""

    def _tenant(self, role: MembershipRole = MembershipRole.OWNER) -> TenantContext:
        return TenantContext(
            user_id="u",
            email="e@test.com",
            organization_id="org-1",
            role=role,
            permissions=ROLE_PERMISSIONS[role],
        )

    async def test_suspended_organization_blocks_by_default(self) -> None:
        dependency = require_permission(Permission.MEMBERS_MANAGE)
        with pytest.raises(OrganizationInactiveError):
            await dependency(
                tenant=self._tenant(),
                org_service=_FakeOrganizationService("suspended"),
            )

    async def test_active_organization_passes(self) -> None:
        dependency = require_permission(Permission.MEMBERS_MANAGE)
        tenant = self._tenant()
        result = await dependency(tenant=tenant, org_service=_active_org())
        assert result is tenant

    async def test_inactive_deactivated_organization_is_not_blocked(self) -> None:
        """This remediation is scoped to SUSPENDED specifically — a
        merely deactivated (INACTIVE) organization is a distinct
        lifecycle state and out of scope here."""
        dependency = require_permission(Permission.MEMBERS_MANAGE)
        tenant = self._tenant()
        result = await dependency(
            tenant=tenant,
            org_service=_FakeOrganizationService("inactive"),
        )
        assert result is tenant

    async def test_allow_when_suspended_opts_out(self) -> None:
        dependency = require_permission(Permission.ORG_MANAGE, allow_when_suspended=True)
        tenant = self._tenant()
        result = await dependency(
            tenant=tenant,
            org_service=_FakeOrganizationService("suspended"),
        )
        assert result is tenant

    async def test_permission_check_runs_before_suspension_check(self) -> None:
        """A caller without the permission at all gets AuthorizationError,
        not OrganizationInactiveError — insufficient privilege is reported
        before organization state, since it doesn't leak anything about
        the organization's status to a caller who shouldn't be looking at
        it in the first place."""
        dependency = require_permission(Permission.MEMBERS_MANAGE)
        tenant = self._tenant(MembershipRole.VIEWER)
        with pytest.raises(AuthorizationError):
            await dependency(
                tenant=tenant,
                org_service=_FakeOrganizationService("suspended"),
            )


class TestEnsureOrganizationMatch:
    def _tenant(self, organization_id: str) -> TenantContext:
        return TenantContext(
            user_id="u",
            email="e@test.com",
            organization_id=organization_id,
            role=MembershipRole.OWNER,
            permissions=ROLE_PERMISSIONS[MembershipRole.OWNER],
        )

    def test_matching_organization_passes_silently(self) -> None:
        tenant = self._tenant("org-1")
        ensure_organization_match("org-1", tenant)  # must not raise

    def test_mismatched_organization_raises(self) -> None:
        tenant = self._tenant("org-1")
        with pytest.raises(AuthorizationError):
            ensure_organization_match("org-2", tenant)
