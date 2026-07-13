"""Unit tests for User and Membership entities."""

import pytest

from redforge.domain.identity.entities import Membership, User
from redforge.domain.identity.events import (
    MembershipCreated,
    MembershipReactivated,
    MembershipRevoked,
    MembershipRoleChanged,
    MembershipSuspended,
    UserActivated,
    UserDeactivated,
    UserRegistered,
    UserSuspended,
)
from redforge.domain.identity.exceptions import (
    InvalidUserTransitionError,
    MembershipNotActiveError,
)
from redforge.domain.identity.value_objects import (
    Email,
    MembershipRole,
    MembershipStatus,
    PasswordHash,
    Permission,
    UserStatus,
)
from redforge.shared.identifiers import EntityId

VALID_HASH = "$2b$12$abcdefghijklmnopqrstuv"


def _register_user(email: str = "test@example.com") -> User:
    return User.register(
        email=Email(email),
        display_name="Test User",
        password_hash=PasswordHash(VALID_HASH),
    )


def _invite_user(email: str = "invited@example.com") -> User:
    return User.invite(email=Email(email), display_name="Invited User")


def _create_membership(
    role: MembershipRole = MembershipRole.MEMBER,
) -> Membership:
    return Membership.create(
        user_id=EntityId.generate(),
        organization_id=EntityId.generate(),
        role=role,
    )


# ─── User Registration ───────────────────────────────────────────────────────


class TestUserRegistration:
    def test_register_sets_active_status(self) -> None:
        user = _register_user()
        assert user.status == UserStatus.ACTIVE
        assert user.is_active is True

    def test_register_sets_email(self) -> None:
        user = _register_user("alice@corp.com")
        assert user.email == Email("alice@corp.com")

    def test_register_sets_display_name(self) -> None:
        user = _register_user()
        assert user.display_name == "Test User"

    def test_register_sets_password_hash(self) -> None:
        user = _register_user()
        assert user.password_hash == PasswordHash(VALID_HASH)

    def test_register_emits_event(self) -> None:
        user = _register_user("new@test.com")
        events = user.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], UserRegistered)
        assert events[0].email == "new@test.com"

    def test_register_generates_unique_id(self) -> None:
        u1 = _register_user("a@b.com")
        u2 = _register_user("c@d.com")
        assert u1.id != u2.id


class TestUserInvitation:
    def test_invite_sets_pending_status(self) -> None:
        user = _invite_user()
        assert user.status == UserStatus.PENDING
        assert user.is_active is False

    def test_invite_has_no_password(self) -> None:
        user = _invite_user()
        assert user.password_hash is None

    def test_invite_emits_registered_event(self) -> None:
        user = _invite_user()
        events = user.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], UserRegistered)


class TestUserSetPassword:
    def test_set_password_activates_pending_user(self) -> None:
        user = _invite_user()
        user.collect_events()
        user.set_password(PasswordHash(VALID_HASH))
        assert user.status == UserStatus.ACTIVE
        assert user.password_hash == PasswordHash(VALID_HASH)

    def test_set_password_emits_activated_for_pending(self) -> None:
        user = _invite_user()
        user.collect_events()
        user.set_password(PasswordHash(VALID_HASH))
        events = user.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], UserActivated)

    def test_set_password_on_active_user_updates_hash(self) -> None:
        user = _register_user()
        user.collect_events()
        new_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
        user.set_password(PasswordHash(new_hash))
        assert user.password_hash == PasswordHash(new_hash)


# ─── User Status Transitions ─────────────────────────────────────────────────


class TestUserActivate:
    def test_activate_inactive_user(self) -> None:
        user = _register_user()
        user.deactivate()
        user.collect_events()
        user.activate()
        assert user.is_active is True

    def test_activate_emits_event(self) -> None:
        user = _register_user()
        user.deactivate()
        user.collect_events()
        user.activate()
        events = user.collect_events()
        assert isinstance(events[0], UserActivated)

    def test_activate_already_active_raises(self) -> None:
        user = _register_user()
        user.collect_events()
        with pytest.raises(InvalidUserTransitionError):
            user.activate()


class TestUserDeactivate:
    def test_deactivate_active_user(self) -> None:
        user = _register_user()
        user.collect_events()
        user.deactivate()
        assert user.status == UserStatus.INACTIVE

    def test_deactivate_emits_event(self) -> None:
        user = _register_user()
        user.collect_events()
        user.deactivate()
        events = user.collect_events()
        assert isinstance(events[0], UserDeactivated)

    def test_deactivate_inactive_raises(self) -> None:
        user = _register_user()
        user.deactivate()
        user.collect_events()
        with pytest.raises(InvalidUserTransitionError):
            user.deactivate()


class TestUserSuspend:
    def test_suspend_active_user(self) -> None:
        user = _register_user()
        user.collect_events()
        user.suspend()
        assert user.status == UserStatus.SUSPENDED

    def test_suspend_emits_event(self) -> None:
        user = _register_user()
        user.collect_events()
        user.suspend()
        events = user.collect_events()
        assert isinstance(events[0], UserSuspended)

    def test_suspend_inactive_raises(self) -> None:
        user = _register_user()
        user.deactivate()
        user.collect_events()
        with pytest.raises(InvalidUserTransitionError):
            user.suspend()


class TestUserEquality:
    def test_same_id_equal(self) -> None:
        user = _register_user()
        user2 = User(
            id=user.id,
            email=Email("other@x.com"),
            display_name="Other",
            password_hash=None,
            status=UserStatus.ACTIVE,
            timestamps=user.timestamps,
        )
        assert user == user2

    def test_different_id_not_equal(self) -> None:
        u1 = _register_user("a@b.com")
        u2 = _register_user("c@d.com")
        assert u1 != u2

    def test_hashable(self) -> None:
        user = _register_user()
        assert len({user, user}) == 1


# ─── Membership ───────────────────────────────────────────────────────────────


class TestMembershipCreation:
    def test_create_sets_active(self) -> None:
        m = _create_membership()
        assert m.is_active is True

    def test_create_sets_role(self) -> None:
        m = _create_membership(MembershipRole.ADMIN)
        assert m.role == MembershipRole.ADMIN

    def test_create_emits_event(self) -> None:
        m = _create_membership()
        events = m.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], MembershipCreated)

    def test_create_generates_unique_id(self) -> None:
        m1 = _create_membership()
        m2 = _create_membership()
        assert m1.id != m2.id


class TestMembershipChangeRole:
    def test_change_role(self) -> None:
        m = _create_membership(MembershipRole.MEMBER)
        m.collect_events()
        m.change_role(MembershipRole.ADMIN)
        assert m.role == MembershipRole.ADMIN

    def test_change_role_emits_event(self) -> None:
        m = _create_membership(MembershipRole.MEMBER)
        m.collect_events()
        m.change_role(MembershipRole.ADMIN)
        events = m.collect_events()
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, MembershipRoleChanged)
        assert event.old_role == "member"
        assert event.new_role == "admin"

    def test_change_role_same_no_op(self) -> None:
        m = _create_membership(MembershipRole.MEMBER)
        m.collect_events()
        m.change_role(MembershipRole.MEMBER)
        assert m.collect_events() == []

    def test_change_role_revoked_raises(self) -> None:
        m = _create_membership()
        m.revoke()
        m.collect_events()
        with pytest.raises(MembershipNotActiveError):
            m.change_role(MembershipRole.ADMIN)


class TestMembershipRevoke:
    def test_revoke(self) -> None:
        m = _create_membership()
        m.collect_events()
        m.revoke()
        assert m.is_active is False

    def test_revoke_emits_event(self) -> None:
        m = _create_membership()
        m.collect_events()
        m.revoke()
        events = m.collect_events()
        assert isinstance(events[0], MembershipRevoked)

    def test_revoke_already_revoked_raises(self) -> None:
        m = _create_membership()
        m.revoke()
        m.collect_events()
        with pytest.raises(MembershipNotActiveError):
            m.revoke()

    def test_revoke_from_suspended_succeeds(self) -> None:
        """Revoke (permanent removal) is valid from SUSPENDED, not just
        ACTIVE — an org should be able to permanently remove someone
        who was already suspended without first reactivating them."""
        m = _create_membership()
        m.suspend()
        m.collect_events()
        m.revoke()
        assert m.status == MembershipStatus.REMOVED


class TestMembershipSuspendReactivate:
    def test_suspend_sets_status(self) -> None:
        m = _create_membership()
        m.collect_events()
        m.suspend()
        assert m.status == MembershipStatus.SUSPENDED
        assert m.is_active is False

    def test_suspend_preserves_role(self) -> None:
        m = _create_membership(MembershipRole.ADMIN)
        m.suspend()
        assert m.role == MembershipRole.ADMIN

    def test_suspend_emits_event(self) -> None:
        m = _create_membership()
        m.collect_events()
        m.suspend()
        events = m.collect_events()
        assert isinstance(events[0], MembershipSuspended)

    def test_suspend_already_suspended_raises(self) -> None:
        m = _create_membership()
        m.suspend()
        with pytest.raises(MembershipNotActiveError):
            m.suspend()

    def test_suspend_removed_raises(self) -> None:
        m = _create_membership()
        m.revoke()
        with pytest.raises(MembershipNotActiveError):
            m.suspend()

    def test_suspended_membership_has_no_permissions(self) -> None:
        m = _create_membership(MembershipRole.OWNER)
        m.suspend()
        assert m.has_permission(Permission.ORG_MANAGE) is False

    def test_reactivate_restores_active(self) -> None:
        m = _create_membership()
        m.suspend()
        m.collect_events()
        m.reactivate()
        assert m.status == MembershipStatus.ACTIVE
        assert m.is_active is True

    def test_reactivate_emits_event(self) -> None:
        m = _create_membership()
        m.suspend()
        m.collect_events()
        m.reactivate()
        events = m.collect_events()
        assert isinstance(events[0], MembershipReactivated)

    def test_reactivate_restores_permissions(self) -> None:
        m = _create_membership(MembershipRole.OWNER)
        m.suspend()
        m.reactivate()
        assert m.has_permission(Permission.ORG_MANAGE) is True

    def test_reactivate_from_active_raises(self) -> None:
        m = _create_membership()
        with pytest.raises(MembershipNotActiveError):
            m.reactivate()

    def test_reactivate_removed_raises(self) -> None:
        """A permanently removed membership can never be reactivated —
        the user must be re-invited (a new Membership created)."""
        m = _create_membership()
        m.revoke()
        with pytest.raises(MembershipNotActiveError):
            m.reactivate()


class TestMembershipPermissions:
    def test_has_permission_owner(self) -> None:
        m = _create_membership(MembershipRole.OWNER)
        assert m.has_permission(Permission.ORG_MANAGE) is True
        assert m.has_permission(Permission.MEMBERS_MANAGE) is True

    def test_has_permission_viewer_limited(self) -> None:
        m = _create_membership(MembershipRole.VIEWER)
        assert m.has_permission(Permission.VALIDATIONS_READ) is True
        assert m.has_permission(Permission.VALIDATIONS_RUN) is False

    def test_revoked_membership_has_no_permissions(self) -> None:
        m = _create_membership(MembershipRole.OWNER)
        m.revoke()
        assert m.has_permission(Permission.ORG_READ) is False

    def test_permissions_property(self) -> None:
        m = _create_membership(MembershipRole.MEMBER)
        perms = m.permissions
        assert Permission.VALIDATIONS_RUN in perms
        assert Permission.MEMBERS_MANAGE not in perms


class TestMembershipEquality:
    def test_same_id_equal(self) -> None:
        m = _create_membership()
        m2 = Membership(
            id=m.id,
            user_id=EntityId.generate(),
            organization_id=EntityId.generate(),
            role=MembershipRole.VIEWER,
            status=MembershipStatus.REMOVED,
            timestamps=m.timestamps,
        )
        assert m == m2

    def test_different_id_not_equal(self) -> None:
        m1 = _create_membership()
        m2 = _create_membership()
        assert m1 != m2
