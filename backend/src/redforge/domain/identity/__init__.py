"""Identity bounded context.

Manages user accounts, organization memberships, roles, and permissions.
Users belong to Organizations through Memberships, each carrying a role
that determines the user's permissions within that Organization.

Public API:
    - User: Account aggregate root.
    - Membership: Organization access aggregate.
    - Repositories: UserRepository, MembershipRepository (Protocols).
    - Value objects: Email, PasswordHash, UserStatus, MembershipRole, Permission.
    - Events: UserRegistered, MembershipCreated, etc.
    - Exceptions: UserNotFoundError, UserAlreadyExistsError, etc.
"""

from redforge.domain.identity.entities import Membership, User
from redforge.domain.identity.repository import MembershipRepository, UserRepository
from redforge.domain.identity.value_objects import (
    Email,
    MembershipRole,
    PasswordHash,
    Permission,
    UserStatus,
)

__all__ = [
    "Email",
    "Membership",
    "MembershipRepository",
    "MembershipRole",
    "PasswordHash",
    "Permission",
    "User",
    "UserRepository",
    "UserStatus",
]
