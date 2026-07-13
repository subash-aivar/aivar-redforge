"""Application use cases for the Identity bounded context.

Use cases orchestrate User and Membership operations:
1. Accept primitive input.
2. Enforce preconditions (email uniqueness, membership existence).
3. Delegate to domain aggregates.
4. Persist via repositories.
5. Return results with collected events.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.identity.entities import Membership, User
from redforge.domain.identity.exceptions import (
    MembershipAlreadyExistsError,
    MembershipNotFoundError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from redforge.domain.identity.value_objects import Email, MembershipRole, PasswordHash
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.identity.events import IdentityEvent
    from redforge.domain.identity.repository import MembershipRepository, UserRepository


# ─── Commands ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RegisterUserCommand:
    """Input for registering a new user."""

    email: str
    display_name: str
    password_hash: str


@dataclass(frozen=True, slots=True)
class InviteMemberCommand:
    """Input for inviting a user to an organization."""

    email: str
    display_name: str
    organization_id: str
    role: str


@dataclass(frozen=True, slots=True)
class ChangeRoleCommand:
    """Input for changing a member's role."""

    membership_id: str
    new_role: str


# ─── Results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class UserResult:
    """Read-only representation of a User at the application boundary."""

    id: str
    email: str
    display_name: str
    status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, user: User) -> UserResult:
        return cls(
            id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            status=str(user.status),
            created_at=user.timestamps.created_at.isoformat(),
            updated_at=user.timestamps.updated_at.isoformat(),
        )


@dataclass(frozen=True, slots=True)
class MembershipResult:
    """Read-only representation of a Membership at the application boundary."""

    id: str
    user_id: str
    organization_id: str
    role: str
    is_active: bool
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, membership: Membership) -> MembershipResult:
        return cls(
            id=str(membership.id),
            user_id=str(membership.user_id),
            organization_id=str(membership.organization_id),
            role=str(membership.role),
            is_active=membership.is_active,
            created_at=membership.timestamps.created_at.isoformat(),
            updated_at=membership.timestamps.updated_at.isoformat(),
        )


# ─── Use Cases ────────────────────────────────────────────────────────────────


class RegisterUserUseCase:
    """Register a new User account.

    Workflow:
    1. Check email uniqueness.
    2. Create User aggregate.
    3. Persist.
    4. Return result with events.
    """

    def __init__(self, user_repository: UserRepository) -> None:
        self._user_repository = user_repository

    async def execute(
        self, command: RegisterUserCommand
    ) -> tuple[UserResult, list[IdentityEvent]]:
        email = Email(command.email)

        if await self._user_repository.email_exists(email):
            raise UserAlreadyExistsError(command.email)

        user = User.register(
            email=email,
            display_name=command.display_name,
            password_hash=PasswordHash(command.password_hash),
        )

        await self._user_repository.save(user)
        events = user.collect_events()

        return UserResult.from_entity(user), events


class InviteMemberUseCase:
    """Invite a user to an Organization.

    Workflow:
    1. Find or create the User (invited users start as PENDING).
    2. Check membership doesn't already exist.
    3. Create Membership.
    4. Persist both.
    5. Return results with events.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        membership_repository: MembershipRepository,
    ) -> None:
        self._user_repository = user_repository
        self._membership_repository = membership_repository

    async def execute(
        self, command: InviteMemberCommand
    ) -> tuple[MembershipResult, list[IdentityEvent]]:
        email = Email(command.email)
        organization_id = EntityId.from_string(command.organization_id)
        role = MembershipRole(command.role)

        # Find existing user or create an invited one
        user = await self._user_repository.get_by_email(email)
        if user is None:
            user = User.invite(email=email, display_name=command.display_name)
            await self._user_repository.save(user)

        # Check no existing membership
        if await self._membership_repository.exists(user.id, organization_id):
            raise MembershipAlreadyExistsError(str(user.id), str(organization_id))

        membership = Membership.create(
            user_id=user.id,
            organization_id=organization_id,
            role=role,
        )

        await self._membership_repository.save(membership)

        all_events = user.collect_events() + membership.collect_events()

        return MembershipResult.from_entity(membership), all_events


class ChangeRoleUseCase:
    """Change a member's role within an Organization.

    Workflow:
    1. Load the Membership.
    2. Invoke change_role behavior.
    3. Persist.
    4. Return result with events.
    """

    def __init__(self, membership_repository: MembershipRepository) -> None:
        self._membership_repository = membership_repository

    async def execute(
        self, command: ChangeRoleCommand
    ) -> tuple[MembershipResult, list[IdentityEvent]]:
        membership_id = EntityId.from_string(command.membership_id)
        membership = await self._membership_repository.get_by_id(membership_id)

        if membership is None:
            raise MembershipNotFoundError(command.membership_id)

        membership.change_role(MembershipRole(command.new_role))

        await self._membership_repository.save(membership)
        events = membership.collect_events()

        return MembershipResult.from_entity(membership), events


class DeactivateUserUseCase:
    """Deactivate a User account.

    Workflow:
    1. Load the User.
    2. Invoke deactivate behavior.
    3. Persist.
    4. Return result with events.
    """

    def __init__(self, user_repository: UserRepository) -> None:
        self._user_repository = user_repository

    async def execute(
        self, user_id: str
    ) -> tuple[UserResult, list[IdentityEvent]]:
        entity_id = EntityId.from_string(user_id)
        user = await self._user_repository.get_by_id(entity_id)

        if user is None:
            raise UserNotFoundError(user_id)

        user.deactivate()

        await self._user_repository.save(user)
        events = user.collect_events()

        return UserResult.from_entity(user), events


class GetUserUseCase:
    """Retrieve a User by id or email.

    Workflow:
    1. Lookup by identifier.
    2. Raise if not found.
    3. Return result.
    """

    def __init__(self, user_repository: UserRepository) -> None:
        self._user_repository = user_repository

    async def execute_by_id(self, user_id: str) -> UserResult:
        entity_id = EntityId.from_string(user_id)
        user = await self._user_repository.get_by_id(entity_id)

        if user is None:
            raise UserNotFoundError(user_id)

        return UserResult.from_entity(user)

    async def execute_by_email(self, email: str) -> UserResult:
        email_vo = Email(email)
        user = await self._user_repository.get_by_email(email_vo)

        if user is None:
            raise UserNotFoundError(email)

        return UserResult.from_entity(user)
