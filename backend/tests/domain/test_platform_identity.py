"""Domain invariant tests for the Platform Identity bounded context."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.domain.platform_identity.entity import PlatformAssignment
from redforge.domain.platform_identity.exceptions import (
    PlatformAssignmentAlreadyRevokedError,
)
from redforge.domain.platform_identity.value_objects import (
    GRANTABLE_PLATFORM_ROLES_M1,
    PLATFORM_ROLE_PERMISSIONS,
    PlatformAssignmentStatus,
    PlatformPermission,
    PlatformRole,
)


def _active_assignment(role: PlatformRole = PlatformRole.SUPER_ADMIN) -> PlatformAssignment:
    return PlatformAssignment(
        id="assign-1",
        user_id="user-1",
        role=role,
        status=PlatformAssignmentStatus.ACTIVE,
        granted_by="user-0",
        granted_at=datetime.now(UTC),
        revoked_by=None,
        revoked_at=None,
        version=1,
    )


def test_active_super_admin_has_all_platform_permissions() -> None:
    assignment = _active_assignment()
    assert assignment.permissions == frozenset(PlatformPermission)


def test_revoked_assignment_has_no_permissions() -> None:
    assignment = _active_assignment().revoke("user-0")
    assert assignment.permissions == frozenset()
    assert assignment.status == PlatformAssignmentStatus.REVOKED
    assert not assignment.is_active


def test_revoke_records_revoker_and_timestamp() -> None:
    assignment = _active_assignment().revoke("revoker-id")
    assert assignment.revoked_by == "revoker-id"
    assert assignment.revoked_at is not None
    assert assignment.version == 2


def test_revoke_twice_raises() -> None:
    revoked = _active_assignment().revoke("user-0")
    with pytest.raises(PlatformAssignmentAlreadyRevokedError):
        revoked.revoke("user-0")


def test_non_super_admin_roles_have_distinct_real_permission_sets_in_m2() -> None:
    """M2 matured SECURITY_ADMIN/SUPPORT/AUDITOR from M1's empty
    placeholders into real, distinct, non-overlapping-with-SUPER_ADMIN's
    exclusive permissions (access grant/revoke) semantics."""
    super_admin_perms = PLATFORM_ROLE_PERMISSIONS[PlatformRole.SUPER_ADMIN]
    for role in (PlatformRole.SECURITY_ADMIN, PlatformRole.SUPPORT, PlatformRole.AUDITOR):
        perms = PLATFORM_ROLE_PERMISSIONS[role]
        assert len(perms) > 0, f"{role} must carry real M2 permissions"
        assert perms < super_admin_perms, f"{role} must be a strict subset of SUPER_ADMIN"
        assert PlatformPermission.PLATFORM_ACCESS_GRANT not in perms
        assert PlatformPermission.PLATFORM_ACCESS_REVOKE not in perms


def test_support_and_auditor_are_read_only() -> None:
    mutation_permissions = {
        PlatformPermission.PLATFORM_USERS_SUSPEND,
        PlatformPermission.PLATFORM_USERS_REACTIVATE,
        PlatformPermission.PLATFORM_ORGANIZATIONS_SUSPEND,
        PlatformPermission.PLATFORM_ORGANIZATIONS_REACTIVATE,
        PlatformPermission.PLATFORM_ACCESS_GRANT,
        PlatformPermission.PLATFORM_ACCESS_REVOKE,
    }
    for role in (PlatformRole.SUPPORT, PlatformRole.AUDITOR):
        assert PLATFORM_ROLE_PERMISSIONS[role].isdisjoint(mutation_permissions)


def test_security_admin_can_mutate_users_and_orgs_but_not_access() -> None:
    perms = PLATFORM_ROLE_PERMISSIONS[PlatformRole.SECURITY_ADMIN]
    assert PlatformPermission.PLATFORM_USERS_SUSPEND in perms
    assert PlatformPermission.PLATFORM_ORGANIZATIONS_SUSPEND in perms
    assert PlatformPermission.PLATFORM_ACCESS_GRANT not in perms
    assert PlatformPermission.PLATFORM_ACCESS_REVOKE not in perms


def test_all_four_platform_roles_are_grantable_in_m2() -> None:
    assert frozenset(PlatformRole) == GRANTABLE_PLATFORM_ROLES_M1


def test_platform_role_permission_table_covers_every_role() -> None:
    """PLATFORM_ROLE_PERMISSIONS must have an entry for every PlatformRole —
    a missing entry would KeyError at authorization time in production.
    """
    for role in PlatformRole:
        assert role in PLATFORM_ROLE_PERMISSIONS


def test_platform_permission_namespace_is_disjoint_from_tenant_permission() -> None:
    """Platform permissions use a 'platform:' prefix distinct from tenant
    Permission's 'org:'/'targets:' etc. — string-level proof the two
    enums can never collide even if compared as raw strings.
    """
    from redforge.domain.identity.value_objects import Permission

    platform_values = {p.value for p in PlatformPermission}
    tenant_values = {p.value for p in Permission}
    assert platform_values.isdisjoint(tenant_values)
