"""Unit tests for Identity use cases."""

import pytest

from redforge.domain.identity.entities import Membership, User
from redforge.domain.identity.events import (
    MembershipCreated,
    UserDeactivated,
    UserRegistered,
)
from redforge.domain.identity.exceptions import (
    MembershipAlreadyExistsError,
    MembershipNotFoundError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from redforge.domain.identity.use_cases import (
    ChangeRoleCommand,
    ChangeRoleUseCase,
    DeactivateUserUseCase,
    GetUserUseCase,
    InviteMemberCommand,
    InviteMemberUseCase,
    RegisterUserCommand,
    RegisterUserUseCase,
)
from redforge.domain.identity.value_objects import (
    Email,
    MembershipRole,
    PasswordHash,
)
from redforge.shared.identifiers import EntityId

VALID_HASH = "$2b$12$abcdefghijklmnopqrstuv"


class InMemoryUserRepository:
    def __init__(self) -> None:
        self._store: dict[str, User] = {}

    async def get_by_id(self, user_id: EntityId) -> User | None:
        return self._store.get(str(user_id))

    async def get_by_email(self, email: Email) -> User | None:
        for user in self._store.values():
            if user.email == email:
                return user
        return None

    async def email_exists(self, email: Email) -> bool:
        return any(u.email == email for u in self._store.values())

    async def save(self, user: User) -> None:
        self._store[str(user.id)] = user


class InMemoryMembershipRepository:
    def __init__(self) -> None:
        self._store: dict[str, Membership] = {}

    async def get_by_id(self, membership_id: EntityId) -> Membership | None:
        return self._store.get(str(membership_id))

    async def get_by_user_and_org(
        self, user_id: EntityId, organization_id: EntityId
    ) -> Membership | None:
        for m in self._store.values():
            if m.user_id == user_id and m.organization_id == organization_id:
                return m
        return None

    async def list_by_user(self, user_id: EntityId) -> list[Membership]:
        return [m for m in self._store.values() if m.user_id == user_id and m.is_active]

    async def list_by_organization(self, organization_id: EntityId) -> list[Membership]:
        return [
            m for m in self._store.values()
            if m.organization_id == organization_id and m.is_active
        ]

    async def exists(self, user_id: EntityId, organization_id: EntityId) -> bool:
        return any(
            m.user_id == user_id and m.organization_id == organization_id
            for m in self._store.values()
        )

    async def save(self, membership: Membership) -> None:
        self._store[str(membership.id)] = membership


class TestRegisterUser:
    async def test_registers_successfully(self) -> None:
        repo = InMemoryUserRepository()
        uc = RegisterUserUseCase(repo)
        result, events = await uc.execute(
            RegisterUserCommand(email="new@test.com", display_name="New", password_hash=VALID_HASH)
        )
        assert result.email == "new@test.com"
        assert result.status == "active"
        assert len(events) == 1
        assert isinstance(events[0], UserRegistered)

    async def test_persists_user(self) -> None:
        repo = InMemoryUserRepository()
        uc = RegisterUserUseCase(repo)
        result, _ = await uc.execute(
            RegisterUserCommand(email="a@b.com", display_name="A", password_hash=VALID_HASH)
        )
        stored = await repo.get_by_id(EntityId.from_string(result.id))
        assert stored is not None

    async def test_duplicate_email_raises(self) -> None:
        repo = InMemoryUserRepository()
        uc = RegisterUserUseCase(repo)
        await uc.execute(
            RegisterUserCommand(email="dup@test.com", display_name="D", password_hash=VALID_HASH)
        )
        with pytest.raises(UserAlreadyExistsError):
            await uc.execute(
                RegisterUserCommand(
                    email="dup@test.com", display_name="D2", password_hash=VALID_HASH
                )
            )

    async def test_invalid_email_raises(self) -> None:
        repo = InMemoryUserRepository()
        uc = RegisterUserUseCase(repo)
        with pytest.raises(ValueError, match="Invalid email"):
            await uc.execute(
                RegisterUserCommand(email="bad", display_name="X", password_hash=VALID_HASH)
            )


class TestInviteMember:
    async def test_invites_new_user(self) -> None:
        user_repo = InMemoryUserRepository()
        membership_repo = InMemoryMembershipRepository()
        uc = InviteMemberUseCase(user_repo, membership_repo)
        org_id = str(EntityId.generate())

        result, events = await uc.execute(
            InviteMemberCommand(
                email="invite@test.com", display_name="Inv", organization_id=org_id, role="member"
            )
        )
        assert result.role == "member"
        assert result.is_active is True
        # UserRegistered + MembershipCreated
        assert any(isinstance(e, UserRegistered) for e in events)
        assert any(isinstance(e, MembershipCreated) for e in events)

    async def test_invites_existing_user(self) -> None:
        user_repo = InMemoryUserRepository()
        membership_repo = InMemoryMembershipRepository()
        # Pre-register user
        user = User.register(
            email=Email("existing@test.com"),
            display_name="Existing",
            password_hash=PasswordHash(VALID_HASH),
        )
        user.collect_events()
        await user_repo.save(user)

        uc = InviteMemberUseCase(user_repo, membership_repo)
        org_id = str(EntityId.generate())

        result, events = await uc.execute(
            InviteMemberCommand(
                email="existing@test.com", display_name="Existing",
                organization_id=org_id, role="admin"
            )
        )
        assert result.role == "admin"
        # Only MembershipCreated (user already exists)
        assert len(events) == 1
        assert isinstance(events[0], MembershipCreated)

    async def test_duplicate_membership_raises(self) -> None:
        user_repo = InMemoryUserRepository()
        membership_repo = InMemoryMembershipRepository()
        uc = InviteMemberUseCase(user_repo, membership_repo)
        org_id = str(EntityId.generate())

        await uc.execute(
            InviteMemberCommand(
                email="x@y.com", display_name="X", organization_id=org_id, role="member"
            )
        )
        with pytest.raises(MembershipAlreadyExistsError):
            await uc.execute(
                InviteMemberCommand(
                    email="x@y.com", display_name="X", organization_id=org_id, role="admin"
                )
            )


class TestChangeRole:
    async def test_changes_role(self) -> None:
        membership_repo = InMemoryMembershipRepository()
        m = Membership.create(
            user_id=EntityId.generate(),
            organization_id=EntityId.generate(),
            role=MembershipRole.MEMBER,
        )
        m.collect_events()
        await membership_repo.save(m)
        uc = ChangeRoleUseCase(membership_repo)

        result, events = await uc.execute(
            ChangeRoleCommand(membership_id=str(m.id), new_role="admin")
        )
        assert result.role == "admin"
        assert len(events) == 1

    async def test_not_found_raises(self) -> None:
        membership_repo = InMemoryMembershipRepository()
        uc = ChangeRoleUseCase(membership_repo)
        with pytest.raises(MembershipNotFoundError):
            await uc.execute(
                ChangeRoleCommand(membership_id=str(EntityId.generate()), new_role="admin")
            )


class TestDeactivateUser:
    async def test_deactivates(self) -> None:
        user_repo = InMemoryUserRepository()
        user = User.register(
            email=Email("u@t.com"), display_name="U", password_hash=PasswordHash(VALID_HASH)
        )
        user.collect_events()
        await user_repo.save(user)
        uc = DeactivateUserUseCase(user_repo)

        result, events = await uc.execute(str(user.id))
        assert result.status == "inactive"
        assert isinstance(events[0], UserDeactivated)

    async def test_not_found_raises(self) -> None:
        user_repo = InMemoryUserRepository()
        uc = DeactivateUserUseCase(user_repo)
        with pytest.raises(UserNotFoundError):
            await uc.execute(str(EntityId.generate()))


class TestGetUser:
    async def test_get_by_id(self) -> None:
        user_repo = InMemoryUserRepository()
        user = User.register(
            email=Email("get@t.com"), display_name="G", password_hash=PasswordHash(VALID_HASH)
        )
        user.collect_events()
        await user_repo.save(user)
        uc = GetUserUseCase(user_repo)

        result = await uc.execute_by_id(str(user.id))
        assert result.email == "get@t.com"

    async def test_get_by_email(self) -> None:
        user_repo = InMemoryUserRepository()
        user = User.register(
            email=Email("find@t.com"), display_name="F", password_hash=PasswordHash(VALID_HASH)
        )
        user.collect_events()
        await user_repo.save(user)
        uc = GetUserUseCase(user_repo)

        result = await uc.execute_by_email("find@t.com")
        assert result.display_name == "F"

    async def test_not_found_raises(self) -> None:
        user_repo = InMemoryUserRepository()
        uc = GetUserUseCase(user_repo)
        with pytest.raises(UserNotFoundError):
            await uc.execute_by_id(str(EntityId.generate()))
