"""Domain entities for the Identity bounded context.

User: Represents an individual account in the platform.
Membership: Represents a User's relationship to an Organization with a role.

User is the aggregate root for account lifecycle.
Membership is the aggregate root for organization access.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Self

from redforge.domain.identity.events import (
    IdentityEvent,
    InvitationAccepted,
    InvitationCreated,
    InvitationRejected,
    InvitationResent,
    InvitationRevoked,
    MembershipCreated,
    MembershipReactivated,
    MembershipRevoked,
    MembershipRoleChanged,
    MembershipSuspended,
    UserActivated,
    UserDeactivated,
    UserRegistered,
    UserSuspended,
    _now,
)
from redforge.domain.identity.exceptions import (
    InvalidUserTransitionError,
    InvitationAlreadyProcessedError,
    InvitationEmailMismatchError,
    InvitationExpiredError,
    MembershipNotActiveError,
    OwnerAssignmentNotAllowedError,
)
from redforge.domain.identity.value_objects import (
    ROLE_PERMISSIONS,
    Email,
    InvitationStatus,
    MembershipRole,
    MembershipStatus,
    PasswordHash,
    Permission,
    UserStatus,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

_DEFAULT_INVITATION_TTL = timedelta(days=7)


class User:
    """User aggregate root.

    Represents an individual account. A User can belong to multiple
    Organizations through Memberships.

    Invariants:
    - A User always has a valid email.
    - Status transitions follow defined rules.
    - Only active users can perform platform operations.
    """

    __slots__ = (
        "_display_name",
        "_email",
        "_events",
        "_id",
        "_password_hash",
        "_status",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        email: Email,
        display_name: str,
        password_hash: PasswordHash | None,
        status: UserStatus,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._email = email
        self._display_name = display_name
        self._password_hash = password_hash
        self._status = status
        self._timestamps = timestamps
        self._events: list[IdentityEvent] = []

    @classmethod
    def register(
        cls,
        email: Email,
        display_name: str,
        password_hash: PasswordHash,
    ) -> User:
        """Register a new User with a password.

        New users start as ACTIVE. Emits UserRegistered event.
        """
        user = cls(
            id=EntityId.generate(),
            email=email,
            display_name=display_name,
            password_hash=password_hash,
            status=UserStatus.ACTIVE,
            timestamps=AuditTimestamps.create(),
        )
        user._record_event(
            UserRegistered(
                occurred_at=_now(),
                user_id=str(user._id),
                email=str(user._email),
            )
        )
        return user

    @classmethod
    def invite(cls, email: Email, display_name: str) -> User:
        """Create a User through invitation (no password yet).

        Invited users start as PENDING until they complete registration.
        Emits UserRegistered event.
        """
        user = cls(
            id=EntityId.generate(),
            email=email,
            display_name=display_name,
            password_hash=None,
            status=UserStatus.PENDING,
            timestamps=AuditTimestamps.create(),
        )
        user._record_event(
            UserRegistered(
                occurred_at=_now(),
                user_id=str(user._id),
                email=str(user._email),
            )
        )
        return user

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def email(self) -> Email:
        return self._email

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def password_hash(self) -> PasswordHash | None:
        return self._password_hash

    @property
    def status(self) -> UserStatus:
        return self._status

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_active(self) -> bool:
        return self._status == UserStatus.ACTIVE

    # ─── Behavior ─────────────────────────────────────────────────────────

    def activate(self) -> None:
        """Activate a pending, inactive, or suspended user.

        Raises:
            InvalidUserTransitionError: If already active.
        """
        self._transition_to(UserStatus.ACTIVE)
        self._record_event(
            UserActivated(occurred_at=_now(), user_id=str(self._id))
        )

    def deactivate(self) -> None:
        """Deactivate an active user.

        Raises:
            InvalidUserTransitionError: If not active.
        """
        self._transition_to(UserStatus.INACTIVE)
        self._record_event(
            UserDeactivated(occurred_at=_now(), user_id=str(self._id))
        )

    def suspend(self) -> None:
        """Suspend an active user due to policy violation.

        Raises:
            InvalidUserTransitionError: If not active.
        """
        self._transition_to(UserStatus.SUSPENDED)
        self._record_event(
            UserSuspended(occurred_at=_now(), user_id=str(self._id))
        )

    def set_password(self, password_hash: PasswordHash) -> None:
        """Set or update the user's password hash.

        For invited users, this completes the registration process.
        Transitions PENDING → ACTIVE if user is pending.
        """
        self._password_hash = password_hash
        self._touch()
        if self._status == UserStatus.PENDING:
            self._status = UserStatus.ACTIVE
            self._record_event(
                UserActivated(occurred_at=_now(), user_id=str(self._id))
            )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[IdentityEvent]:
        """Return and clear all pending domain events."""
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _transition_to(self, target: UserStatus) -> None:
        if not self._can_transition_to(target):
            raise InvalidUserTransitionError(
                current_status=str(self._status),
                target_status=str(target),
            )
        self._status = target
        self._touch()

    def _can_transition_to(self, target: UserStatus) -> bool:
        """Define valid user status transitions.

        ACTIVE → INACTIVE, SUSPENDED
        INACTIVE → ACTIVE
        PENDING → ACTIVE
        SUSPENDED → ACTIVE
        """
        valid: dict[UserStatus, set[UserStatus]] = {
            UserStatus.ACTIVE: {UserStatus.INACTIVE, UserStatus.SUSPENDED},
            UserStatus.INACTIVE: {UserStatus.ACTIVE},
            UserStatus.PENDING: {UserStatus.ACTIVE},
            UserStatus.SUSPENDED: {UserStatus.ACTIVE},
        }
        return target in valid.get(self._status, set())

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: IdentityEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, User):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"User(id={self._id}, email={self._email}, status={self._status})"


class Membership:
    """Membership aggregate root.

    Represents a User's role within an Organization. A User can have
    multiple Memberships (one per Organization).

    Invariants:
    - A Membership always references a valid User and Organization.
    - Role determines permissions within the Organization.
    - Only ACTIVE memberships grant access (SUSPENDED and REMOVED do not).
    - Last-owner protection and self-escalation prevention are enforced
      by the application layer (application/memberships/service.py),
      which has the cross-membership context (counting other owners,
      knowing the acting user's identity) a single aggregate cannot see.
    """

    __slots__ = (
        "_events",
        "_id",
        "_organization_id",
        "_role",
        "_status",
        "_timestamps",
        "_user_id",
    )

    def __init__(
        self,
        id: EntityId,
        user_id: EntityId,
        organization_id: EntityId,
        role: MembershipRole,
        status: MembershipStatus,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._user_id = user_id
        self._organization_id = organization_id
        self._role = role
        self._status = status
        self._timestamps = timestamps
        self._events: list[IdentityEvent] = []

    @classmethod
    def create(
        cls,
        user_id: EntityId,
        organization_id: EntityId,
        role: MembershipRole,
    ) -> Membership:
        """Create a new active Membership. Emits MembershipCreated event."""
        membership = cls(
            id=EntityId.generate(),
            user_id=user_id,
            organization_id=organization_id,
            role=role,
            status=MembershipStatus.ACTIVE,
            timestamps=AuditTimestamps.create(),
        )
        membership._record_event(
            MembershipCreated(
                occurred_at=_now(),
                membership_id=str(membership._id),
                user_id=str(user_id),
                organization_id=str(organization_id),
                role=str(role),
            )
        )
        return membership

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def user_id(self) -> EntityId:
        return self._user_id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def role(self) -> MembershipRole:
        return self._role

    @property
    def status(self) -> MembershipStatus:
        return self._status

    @property
    def is_active(self) -> bool:
        """True only when status is ACTIVE. Kept as the primary read for
        existing callers (has_permission, application services, API) —
        `status` is the richer view for callers that need to distinguish
        SUSPENDED from REMOVED."""
        return self._status == MembershipStatus.ACTIVE

    @property
    def is_owner(self) -> bool:
        return self._role == MembershipRole.OWNER

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def permissions(self) -> frozenset[Permission]:
        """The permissions granted by this membership's role."""
        return ROLE_PERMISSIONS[self._role]

    # ─── Behavior ─────────────────────────────────────────────────────────

    def change_role(self, new_role: MembershipRole) -> None:
        """Change the member's role within the organization.

        Raises:
            MembershipNotActiveError: If suspended or removed.
        """
        self._require_active()
        if self._role == new_role:
            return
        old_role = self._role
        self._role = new_role
        self._touch()
        self._record_event(
            MembershipRoleChanged(
                occurred_at=_now(),
                membership_id=str(self._id),
                user_id=str(self._user_id),
                organization_id=str(self._organization_id),
                old_role=str(old_role),
                new_role=str(new_role),
            )
        )

    def suspend(self) -> None:
        """Temporarily pause this membership's access.

        Reversible via reactivate(). Role is preserved.

        Raises:
            MembershipNotActiveError: If not currently active.
        """
        self._require_active()
        self._status = MembershipStatus.SUSPENDED
        self._touch()
        self._record_event(
            MembershipSuspended(
                occurred_at=_now(),
                membership_id=str(self._id),
                user_id=str(self._user_id),
                organization_id=str(self._organization_id),
            )
        )

    def reactivate(self) -> None:
        """Restore a suspended membership to active.

        Raises:
            MembershipNotActiveError: If not currently suspended (in
            particular, a REMOVED membership cannot be reactivated — a
            removed user must be re-invited).
        """
        if self._status != MembershipStatus.SUSPENDED:
            raise MembershipNotActiveError(str(self._id), str(self._status))
        self._status = MembershipStatus.ACTIVE
        self._touch()
        self._record_event(
            MembershipReactivated(
                occurred_at=_now(),
                membership_id=str(self._id),
                user_id=str(self._user_id),
                organization_id=str(self._organization_id),
            )
        )

    def revoke(self) -> None:
        """Permanently remove this membership.

        Valid from ACTIVE or SUSPENDED. Terminal — a removed user must
        be re-invited (a new Membership created) to regain access.

        Raises:
            MembershipNotActiveError: If already removed.
        """
        if self._status == MembershipStatus.REMOVED:
            raise MembershipNotActiveError(str(self._id), str(self._status))
        self._status = MembershipStatus.REMOVED
        self._touch()
        self._record_event(
            MembershipRevoked(
                occurred_at=_now(),
                membership_id=str(self._id),
                user_id=str(self._user_id),
                organization_id=str(self._organization_id),
            )
        )

    def has_permission(self, permission: Permission) -> bool:
        """Check if this membership grants the specified permission."""
        if not self.is_active:
            return False
        return permission in self.permissions

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[IdentityEvent]:
        """Return and clear all pending domain events."""
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_active(self) -> None:
        if not self.is_active:
            raise MembershipNotActiveError(str(self._id), str(self._status))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: IdentityEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Membership):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"Membership(id={self._id}, user={self._user_id}, "
            f"org={self._organization_id}, role={self._role})"
        )


class Invitation:
    """Invitation aggregate root.

    Represents a pending offer for a specific email address to join an
    Organization with a specific role. Accepting an Invitation creates a
    Membership — the Invitation itself never grants access.

    Security design:
    - The bearer token handed to the invitee is never persisted. Only
      its SHA-256 hash (`token_hash`) is stored, exactly the same
      pattern used for password hashes — a database read (or leak)
      cannot be used to forge acceptance. `Invitation.create()` and
      `.resend()` are the only places a plaintext token is ever
      produced, and each returns it exactly once to its caller.
    - Token comparison at acceptance time must use a constant-time
      comparison (see application/invitations/service.py) to avoid
      timing side-channels — the domain layer stores/compares hashes,
      not raw secrets, so this entity has no comparison logic itself.

    Invariants:
    - Always references a valid Organization, target email, and role.
    - Only a PENDING, non-expired Invitation can be accepted or rejected.
    - Acceptance is idempotent for the SAME accepting user (see accept()).
    - Terminal states (ACCEPTED, REJECTED, REVOKED) never transition again.
    """

    __slots__ = (
        "_accepted_by_user_id",
        "_email",
        "_events",
        "_expires_at",
        "_id",
        "_invited_by_user_id",
        "_organization_id",
        "_role",
        "_status",
        "_timestamps",
        "_token_hash",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        email: Email,
        role: MembershipRole,
        invited_by_user_id: EntityId,
        token_hash: str,
        status: InvitationStatus,
        expires_at: datetime,
        timestamps: AuditTimestamps,
        accepted_by_user_id: EntityId | None = None,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._email = email
        self._role = role
        self._invited_by_user_id = invited_by_user_id
        self._token_hash = token_hash
        self._status = status
        self._expires_at = expires_at
        self._timestamps = timestamps
        self._accepted_by_user_id = accepted_by_user_id
        self._events: list[IdentityEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        email: Email,
        role: MembershipRole,
        invited_by_user_id: EntityId,
        ttl: timedelta = _DEFAULT_INVITATION_TTL,
    ) -> tuple[Self, str]:
        """Create a new pending Invitation.

        Returns (invitation, plaintext_token). The plaintext token is
        the only copy that will ever exist outside this call — the
        caller (application layer) is responsible for delivering it
        (e.g. by email) and must not log or persist it. Only its hash
        is stored on the entity.

        Raises:
            OwnerAssignmentNotAllowedError: If role is OWNER. Accepting
                an invitation creates a Membership directly at
                `role` (see InvitationService.accept) with no
                transfer_ownership() involved — inviting someone
                straight to OWNER would be an undetected second path to
                granting ownership, bypassing the atomic
                promote-then-demote transfer_ownership() guarantees
                entirely (an org could end up with two OWNERs, or an
                OWNER granted by a non-owner ADMIN's invite). OWNER
                status can only move via an existing member being
                promoted through transfer_ownership().
        """
        if role == MembershipRole.OWNER:
            raise OwnerAssignmentNotAllowedError(str(email), context="invitation")
        token = secrets.token_urlsafe(32)
        expires_at = utc_now() + ttl
        invitation = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            email=email,
            role=role,
            invited_by_user_id=invited_by_user_id,
            token_hash=_hash_token(token),
            status=InvitationStatus.PENDING,
            expires_at=expires_at,
            timestamps=AuditTimestamps.create(),
        )
        invitation._record_event(
            InvitationCreated(
                occurred_at=_now(),
                invitation_id=str(invitation._id),
                organization_id=str(organization_id),
                email=str(email),
                role=str(role),
                invited_by_user_id=str(invited_by_user_id),
                expires_at=expires_at,
            )
        )
        return invitation, token

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def email(self) -> Email:
        return self._email

    @property
    def role(self) -> MembershipRole:
        return self._role

    @property
    def invited_by_user_id(self) -> EntityId:
        return self._invited_by_user_id

    @property
    def token_hash(self) -> str:
        return self._token_hash

    @property
    def status(self) -> InvitationStatus:
        return self._status

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def accepted_by_user_id(self) -> EntityId | None:
        return self._accepted_by_user_id

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_pending(self) -> bool:
        return self._status == InvitationStatus.PENDING

    def is_expired(self, now: datetime | None = None) -> bool:
        """Expiry is computed from `now`, never stored as a transition —
        so a PENDING invitation that has simply aged past its
        expires_at is reported as expired without needing a background
        job to flip its status."""
        current = now if now is not None else utc_now()
        return current > self._expires_at

    # ─── Behavior ─────────────────────────────────────────────────────────

    def accept(self, accepting_user_id: EntityId, accepting_email: Email) -> None:
        """Accept this invitation, on behalf of `accepting_user_id`.

        Idempotent: calling accept() again with the SAME accepting user
        on an already-ACCEPTED invitation is a no-op (no event
        re-emitted, no exception) — this covers double-submits and
        network-retry replays of the exact same acceptance. Any other
        combination (different user, or a REJECTED/REVOKED invitation)
        raises InvitationAlreadyProcessedError.

        Raises:
            InvitationExpiredError: If past expiry.
            InvitationEmailMismatchError: If accepting_email doesn't
                match the invited address.
            InvitationAlreadyProcessedError: If already finalized by a
                different outcome.
        """
        if self._status == InvitationStatus.ACCEPTED:
            if self._accepted_by_user_id == accepting_user_id:
                return  # idempotent replay of the same successful acceptance
            raise InvitationAlreadyProcessedError(str(self._id), str(self._status))
        if self._status != InvitationStatus.PENDING:
            raise InvitationAlreadyProcessedError(str(self._id), str(self._status))
        if self.is_expired():
            raise InvitationExpiredError(str(self._id))
        if accepting_email != self._email:
            raise InvitationEmailMismatchError(str(self._id))

        self._status = InvitationStatus.ACCEPTED
        self._accepted_by_user_id = accepting_user_id
        self._touch()
        self._record_event(
            InvitationAccepted(
                occurred_at=_now(),
                invitation_id=str(self._id),
                organization_id=str(self._organization_id),
                email=str(self._email),
                accepted_by_user_id=str(accepting_user_id),
            )
        )

    def reject(self) -> None:
        """Decline this invitation.

        Raises:
            InvitationAlreadyProcessedError: If not PENDING.
        """
        self._require_pending()
        self._status = InvitationStatus.REJECTED
        self._touch()
        self._record_event(
            InvitationRejected(
                occurred_at=_now(),
                invitation_id=str(self._id),
                organization_id=str(self._organization_id),
                email=str(self._email),
            )
        )

    def revoke(self, revoked_by_user_id: EntityId) -> None:
        """Cancel this invitation before it is acted on.

        Raises:
            InvitationAlreadyProcessedError: If not PENDING.
        """
        self._require_pending()
        self._status = InvitationStatus.REVOKED
        self._touch()
        self._record_event(
            InvitationRevoked(
                occurred_at=_now(),
                invitation_id=str(self._id),
                organization_id=str(self._organization_id),
                email=str(self._email),
                revoked_by_user_id=str(revoked_by_user_id),
            )
        )

    def resend(self, ttl: timedelta = _DEFAULT_INVITATION_TTL) -> str:
        """Regenerate the token and expiry for a still-pending invitation.

        Returns the new plaintext token (same one-time-delivery contract
        as create()). The OLD token is immediately invalidated — its
        hash no longer matches `token_hash` after this call, so a
        previously-sent email link stops working the moment a new one
        is issued (prevents an attacker who intercepted an old email
        from later racing a legitimate resend).

        Raises:
            InvitationAlreadyProcessedError: If not PENDING.
        """
        self._require_pending()
        token = secrets.token_urlsafe(32)
        self._token_hash = _hash_token(token)
        self._expires_at = utc_now() + ttl
        self._touch()
        self._record_event(
            InvitationResent(
                occurred_at=_now(),
                invitation_id=str(self._id),
                organization_id=str(self._organization_id),
                email=str(self._email),
                expires_at=self._expires_at,
            )
        )
        return token

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[IdentityEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_pending(self) -> None:
        if self._status != InvitationStatus.PENDING:
            raise InvitationAlreadyProcessedError(str(self._id), str(self._status))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: IdentityEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Invitation):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"Invitation(id={self._id}, org={self._organization_id}, "
            f"email={self._email}, status={self._status})"
        )


def _hash_token(token: str) -> str:
    """SHA-256 hash of an invitation token for at-rest storage.

    Not a password hash (no need for Argon2/bcrypt's deliberate
    slowness) — this is a high-entropy (256-bit) random token, not a
    human-chosen secret subject to brute-force guessing, so a fast
    cryptographic hash is the correct tool (same reasoning as API key
    hashing at Stripe/GitHub).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
