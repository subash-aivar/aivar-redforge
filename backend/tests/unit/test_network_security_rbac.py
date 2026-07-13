"""RBAC matrix tests for the M16 NETWORK_SECURITY_READ/MANAGE
permissions — every role's grant must be intentional, not accidental."""

from __future__ import annotations

from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole, Permission


class TestNetworkSecurityPermissionMatrix:
    def test_owner_has_read_and_manage(self) -> None:
        perms = ROLE_PERMISSIONS[MembershipRole.OWNER]
        assert Permission.NETWORK_SECURITY_READ in perms
        assert Permission.NETWORK_SECURITY_MANAGE in perms

    def test_admin_has_read_and_manage(self) -> None:
        perms = ROLE_PERMISSIONS[MembershipRole.ADMIN]
        assert Permission.NETWORK_SECURITY_READ in perms
        assert Permission.NETWORK_SECURITY_MANAGE in perms

    def test_security_manager_has_read_and_manage(self) -> None:
        perms = ROLE_PERMISSIONS[MembershipRole.SECURITY_MANAGER]
        assert Permission.NETWORK_SECURITY_READ in perms
        assert Permission.NETWORK_SECURITY_MANAGE in perms

    def test_analyst_has_read_only(self) -> None:
        perms = ROLE_PERMISSIONS[MembershipRole.ANALYST]
        assert Permission.NETWORK_SECURITY_READ in perms
        assert Permission.NETWORK_SECURITY_MANAGE not in perms

    def test_member_has_read_only(self) -> None:
        perms = ROLE_PERMISSIONS[MembershipRole.MEMBER]
        assert Permission.NETWORK_SECURITY_READ in perms
        assert Permission.NETWORK_SECURITY_MANAGE not in perms

    def test_viewer_has_read_only(self) -> None:
        perms = ROLE_PERMISSIONS[MembershipRole.VIEWER]
        assert Permission.NETWORK_SECURITY_READ in perms
        assert Permission.NETWORK_SECURITY_MANAGE not in perms

    def test_every_role_is_present_in_matrix(self) -> None:
        for role in MembershipRole:
            assert role in ROLE_PERMISSIONS
