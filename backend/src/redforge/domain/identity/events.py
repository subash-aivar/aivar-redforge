"""Domain events for the Identity bounded context.

Events represent facts about user and membership lifecycle transitions.
They are collected by aggregates and published after successful persistence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class IdentityEvent:
    """Base class for all Identity domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class UserRegistered(IdentityEvent):
    """A new User account was registered."""

    user_id: str
    email: str


@dataclass(frozen=True, slots=True)
class UserActivated(IdentityEvent):
    """A User account was activated (completed registration or reactivated)."""

    user_id: str


@dataclass(frozen=True, slots=True)
class UserDeactivated(IdentityEvent):
    """A User account was deactivated."""

    user_id: str


@dataclass(frozen=True, slots=True)
class UserSuspended(IdentityEvent):
    """A User account was suspended."""

    user_id: str


@dataclass(frozen=True, slots=True)
class MembershipCreated(IdentityEvent):
    """A User was added to an Organization."""

    membership_id: str
    user_id: str
    organization_id: str
    role: str


@dataclass(frozen=True, slots=True)
class MembershipRoleChanged(IdentityEvent):
    """A Member's role within an Organization was changed."""

    membership_id: str
    user_id: str
    organization_id: str
    old_role: str
    new_role: str


@dataclass(frozen=True, slots=True)
class MembershipRevoked(IdentityEvent):
    """A Member was removed from an Organization."""

    membership_id: str
    user_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class MembershipSuspended(IdentityEvent):
    """A Member's access to an Organization was temporarily paused."""

    membership_id: str
    user_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class MembershipReactivated(IdentityEvent):
    """A previously suspended Membership was restored to active."""

    membership_id: str
    user_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class OwnershipTransferred(IdentityEvent):
    """Organization ownership moved from one Membership to another."""

    organization_id: str
    previous_owner_membership_id: str
    previous_owner_user_id: str
    new_owner_membership_id: str
    new_owner_user_id: str


@dataclass(frozen=True, slots=True)
class InvitationCreated(IdentityEvent):
    """An Invitation to join an Organization was sent."""

    invitation_id: str
    organization_id: str
    email: str
    role: str
    invited_by_user_id: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class InvitationResent(IdentityEvent):
    """An existing pending Invitation was resent with a fresh token/expiry."""

    invitation_id: str
    organization_id: str
    email: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class InvitationAccepted(IdentityEvent):
    """An Invitation was accepted, creating a Membership."""

    invitation_id: str
    organization_id: str
    email: str
    accepted_by_user_id: str


@dataclass(frozen=True, slots=True)
class InvitationRejected(IdentityEvent):
    """An Invitation was explicitly declined by the invitee."""

    invitation_id: str
    organization_id: str
    email: str


@dataclass(frozen=True, slots=True)
class InvitationRevoked(IdentityEvent):
    """An Invitation was cancelled by the organization before acceptance."""

    invitation_id: str
    organization_id: str
    email: str
    revoked_by_user_id: str


def _now() -> datetime:
    """Internal helper for event timestamp generation."""
    return utc_now()
