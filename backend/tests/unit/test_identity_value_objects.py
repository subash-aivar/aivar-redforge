"""Unit tests for Identity value objects."""

import pytest

from redforge.domain.identity.value_objects import (
    ROLE_PERMISSIONS,
    Email,
    MembershipRole,
    PasswordHash,
    Permission,
    UserStatus,
)


class TestEmail:
    def test_valid_email(self) -> None:
        email = Email("user@example.com")
        assert email.value == "user@example.com"

    def test_normalizes_to_lowercase(self) -> None:
        email = Email("User@Example.COM")
        assert email.value == "user@example.com"

    def test_strips_whitespace(self) -> None:
        email = Email("  user@example.com  ")
        assert email.value == "user@example.com"

    def test_complex_valid_email(self) -> None:
        email = Email("first.last+tag@sub.domain.org")
        assert email.value == "first.last+tag@sub.domain.org"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid email"):
            Email("")

    def test_no_at_sign_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid email"):
            Email("userexample.com")

    def test_no_domain_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid email"):
            Email("user@")

    def test_no_tld_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid email"):
            Email("user@domain")

    def test_too_long_raises(self) -> None:
        long_email = "a" * 250 + "@example.com"
        with pytest.raises(ValueError, match="at most 254"):
            Email(long_email)

    def test_equality(self) -> None:
        assert Email("a@b.com") == Email("A@B.COM")
        assert Email("a@b.com") != Email("x@y.com")

    def test_hashable(self) -> None:
        email_set = {Email("a@b.com"), Email("A@B.COM")}
        assert len(email_set) == 1

    def test_not_equal_to_string(self) -> None:
        assert Email("a@b.com") != "a@b.com"

    def test_str(self) -> None:
        assert str(Email("user@test.io")) == "user@test.io"

    def test_repr(self) -> None:
        assert "Email(" in repr(Email("a@b.com"))


class TestPasswordHash:
    def test_valid_hash(self) -> None:
        h = PasswordHash("$2b$12$abcdefghijklmnopqrstuv")
        assert h.value == "$2b$12$abcdefghijklmnopqrstuv"

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="valid hash string"):
            PasswordHash("short")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="valid hash string"):
            PasswordHash("")

    def test_repr_hides_value(self) -> None:
        h = PasswordHash("$2b$12$abcdefghijklmnopqrstuv")
        assert "***" in repr(h)
        assert "$2b$12$" not in repr(h)

    def test_equality(self) -> None:
        h1 = PasswordHash("$2b$12$abcdefghijklmnopqrstuv")
        h2 = PasswordHash("$2b$12$abcdefghijklmnopqrstuv")
        assert h1 == h2

    def test_hashable(self) -> None:
        h = PasswordHash("$2b$12$abcdefghijklmnopqrstuv")
        assert hash(h) == hash(PasswordHash("$2b$12$abcdefghijklmnopqrstuv"))


class TestUserStatus:
    def test_values(self) -> None:
        assert UserStatus.ACTIVE == "active"
        assert UserStatus.INACTIVE == "inactive"
        assert UserStatus.PENDING == "pending"
        assert UserStatus.SUSPENDED == "suspended"

    def test_is_str(self) -> None:
        assert isinstance(UserStatus.ACTIVE, str)


class TestMembershipRole:
    def test_values(self) -> None:
        assert MembershipRole.OWNER == "owner"
        assert MembershipRole.ADMIN == "admin"
        assert MembershipRole.MEMBER == "member"
        assert MembershipRole.VIEWER == "viewer"


class TestPermission:
    def test_has_expected_permissions(self) -> None:
        assert Permission.ORG_READ == "org:read"
        assert Permission.VALIDATIONS_RUN == "validations:run"
        assert Permission.EVIDENCE_READ == "evidence:read"


class TestRolePermissions:
    def test_owner_has_all_permissions(self) -> None:
        owner_perms = ROLE_PERMISSIONS[MembershipRole.OWNER]
        for perm in Permission:
            assert perm in owner_perms

    def test_viewer_has_read_only(self) -> None:
        viewer_perms = ROLE_PERMISSIONS[MembershipRole.VIEWER]
        assert Permission.ORG_READ in viewer_perms
        assert Permission.VALIDATIONS_RUN not in viewer_perms
        assert Permission.TARGETS_CREATE not in viewer_perms
        assert Permission.MEMBERS_INVITE not in viewer_perms

    def test_member_can_run_validations(self) -> None:
        member_perms = ROLE_PERMISSIONS[MembershipRole.MEMBER]
        assert Permission.VALIDATIONS_RUN in member_perms
        assert Permission.TARGETS_CREATE in member_perms

    def test_admin_can_manage_members(self) -> None:
        admin_perms = ROLE_PERMISSIONS[MembershipRole.ADMIN]
        assert Permission.MEMBERS_MANAGE in admin_perms
        assert Permission.MEMBERS_INVITE in admin_perms

    def test_role_hierarchy(self) -> None:
        viewer = ROLE_PERMISSIONS[MembershipRole.VIEWER]
        member = ROLE_PERMISSIONS[MembershipRole.MEMBER]
        admin = ROLE_PERMISSIONS[MembershipRole.ADMIN]
        owner = ROLE_PERMISSIONS[MembershipRole.OWNER]
        assert viewer.issubset(member)
        assert member.issubset(admin)
        assert admin.issubset(owner)
