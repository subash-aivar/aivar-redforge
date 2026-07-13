"""Repository interfaces for the Identity bounded context.

These protocols define the persistence contracts for User, Membership,
and Invitation aggregates. Implementations live in the infrastructure
layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.identity.entities import Invitation, Membership, User
    from redforge.domain.identity.value_objects import Email
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class UserRepository(Protocol):
    """Port for User persistence operations."""

    async def get_by_id(self, user_id: EntityId) -> User | None:
        """Retrieve a User by their unique identifier."""
        ...

    async def get_by_email(self, email: Email) -> User | None:
        """Retrieve a User by their email address."""
        ...

    async def email_exists(self, email: Email) -> bool:
        """Check whether an email is already registered."""
        ...

    async def save(self, user: User) -> None:
        """Persist a new or updated User."""
        ...


@runtime_checkable
class MembershipRepository(Protocol):
    """Port for Membership persistence operations."""

    async def get_by_id(self, membership_id: EntityId) -> Membership | None:
        """Retrieve a Membership by its unique identifier."""
        ...

    async def get_by_user_and_org(
        self, user_id: EntityId, organization_id: EntityId
    ) -> Membership | None:
        """Retrieve a User's Membership in a specific Organization."""
        ...

    async def list_by_user(self, user_id: EntityId) -> list[Membership]:
        """List all active Memberships for a User."""
        ...

    async def list_by_organization(self, organization_id: EntityId) -> list[Membership]:
        """List all active Memberships within an Organization."""
        ...

    async def exists(self, user_id: EntityId, organization_id: EntityId) -> bool:
        """Check whether a Membership already exists for a User in an Organization."""
        ...

    async def count_active_owners(self, organization_id: EntityId) -> int:
        """Count ACTIVE memberships with role=OWNER in an Organization.

        The last-owner-protection invariant (application/memberships/
        service.py) depends on this: an operation that would remove,
        suspend, or demote an OWNER is only safe when this count is >= 2
        before the operation completes.
        """
        ...

    async def save(self, membership: Membership) -> None:
        """Persist a new or updated Membership."""
        ...


@runtime_checkable
class InvitationRepository(Protocol):
    """Port for Invitation persistence operations."""

    async def get_by_id(self, invitation_id: EntityId) -> Invitation | None:
        """Retrieve an Invitation by its unique identifier."""
        ...

    async def get_by_token_hash(self, token_hash: str) -> Invitation | None:
        """Retrieve an Invitation by its token hash — the lookup used at
        acceptance/rejection time, when the caller has a plaintext token
        (hashed by the caller) but not the invitation ID."""
        ...

    async def get_pending_by_org_and_email(
        self, organization_id: EntityId, email: Email
    ) -> Invitation | None:
        """Find an existing PENDING invitation for (org, email), used to
        enforce duplicate-invitation prevention and to locate the
        invitation a resend operates on."""
        ...

    async def list_by_organization(
        self, organization_id: EntityId, status: str | None = None
    ) -> list[Invitation]:
        """List Invitations for an Organization, optionally filtered by status."""
        ...

    async def save(self, invitation: Invitation) -> None:
        """Persist a new or updated Invitation."""
        ...
