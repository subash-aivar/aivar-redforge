"""Aggregates for the Security Authorization bounded context (M10).

SecurityAuthorization is the canonical, tenant-owned authorization
record for future active security-testing actions. AuthorizationApproval
is a separate, small aggregate recording exactly one approval decision
for an authorization — kept separate (rather than nested inside
SecurityAuthorization) so its history is immutable and independently
auditable, mirroring how Invitation and Membership are separate,
cross-referenced aggregates in domain/identity/entities.py.

Reapproval policy: REJECTED and EXPIRED are terminal. There is no
transition back to PENDING_APPROVAL or ACTIVE from any terminal state —
a requester who wants to try again creates a brand new DRAFT
authorization. This keeps every AuthorizationApproval row an immutable,
never-overwritten historical fact instead of a mutable-in-place record
that could be resubmitted and silently lose its original decision.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from redforge.domain.authorization.events import (
    AuthorizationApproved,
    AuthorizationCreated,
    AuthorizationEvent,
    AuthorizationExpired,
    AuthorizationRejected,
    AuthorizationRevoked,
    AuthorizationSubmittedForApproval,
    _now,
)
from redforge.domain.authorization.exceptions import (
    ApprovalAlreadyDecidedError,
    EmptyAuthorizationScopeError,
    InvalidAuthorizationTransitionError,
    SelfApprovalForbiddenError,
)
from redforge.domain.authorization.value_objects import (
    ActionClass,
    ApprovalDecision,
    AuthorizationScopeEntry,
    AuthorizationStatus,
    ValidityWindow,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from datetime import datetime


class SecurityAuthorization:
    """SecurityAuthorization aggregate root.

    Invariants:
    - Always tenant-owned (organization_id never changes).
    - Only DRAFT authorizations may have their scope/action classes
      mutated.
    - submit_for_approval() requires at least one scope entity and one
      action class.
    - Only PENDING_APPROVAL authorizations may be approved or rejected.
    - Only ACTIVE authorizations may be revoked.
    - The requester can never approve or reject their own authorization
      (SelfApprovalForbiddenError), unconditionally — no role bypasses
      this, including Super Admin (see approve()/reject() docstrings).
    """

    __slots__ = (
        "_action_classes",
        "_events",
        "_id",
        "_organization_id",
        "_requester_user_id",
        "_scope",
        "_status",
        "_timestamps",
        "_validity",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        requester_user_id: EntityId,
        status: AuthorizationStatus,
        action_classes: set[ActionClass],
        scope: set[AuthorizationScopeEntry],
        validity: ValidityWindow,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._requester_user_id = requester_user_id
        self._status = status
        self._action_classes = action_classes
        self._scope = scope
        self._validity = validity
        self._timestamps = timestamps
        self._events: list[AuthorizationEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        requester_user_id: EntityId,
        validity: ValidityWindow,
        action_classes: set[ActionClass] | None = None,
        scope: set[AuthorizationScopeEntry] | None = None,
    ) -> Self:
        """Create a new SecurityAuthorization in DRAFT status.

        A client can never create anything other than DRAFT — the only
        way to reach ACTIVE is submit_for_approval() followed by a
        distinct approver's approve() call.
        """
        authorization = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            requester_user_id=requester_user_id,
            status=AuthorizationStatus.DRAFT,
            action_classes=set(action_classes or set()),
            scope=set(scope or set()),
            validity=validity,
            timestamps=AuditTimestamps.create(),
        )
        authorization._record_event(
            AuthorizationCreated(
                occurred_at=_now(),
                authorization_id=str(authorization._id),
                organization_id=str(organization_id),
                requester_user_id=str(requester_user_id),
            )
        )
        return authorization

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def requester_user_id(self) -> EntityId:
        return self._requester_user_id

    @property
    def status(self) -> AuthorizationStatus:
        return self._status

    @property
    def action_classes(self) -> frozenset[ActionClass]:
        return frozenset(self._action_classes)

    @property
    def scope(self) -> frozenset[AuthorizationScopeEntry]:
        return frozenset(self._scope)

    @property
    def validity(self) -> ValidityWindow:
        return self._validity

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    def is_active_now(self, now: datetime) -> bool:
        """True only when status is ACTIVE AND the current time is
        within the validity window. This is the time-of-use check —
        never trust a stored ACTIVE status alone (see ValidityWindow's
        docstring)."""
        return self._status == AuthorizationStatus.ACTIVE and self._validity.contains(now)

    def covers(self, action_class: ActionClass, entities: set[AuthorizationScopeEntry]) -> bool:
        """True if this authorization's scope grants `action_class` for
        every entity in `entities`. Exact matching only — no substring
        or display-name matching."""
        if action_class not in self._action_classes:
            return False
        return entities.issubset(self._scope)

    # ─── Composition (DRAFT only) ─────────────────────────────────────────

    def add_action_class(self, action_class: ActionClass) -> None:
        self._require_draft()
        self._action_classes.add(action_class)
        self._touch()

    def remove_action_class(self, action_class: ActionClass) -> None:
        self._require_draft()
        self._action_classes.discard(action_class)
        self._touch()

    def add_scope_entry(self, entry: AuthorizationScopeEntry) -> None:
        self._require_draft()
        self._scope.add(entry)
        self._touch()

    def remove_scope_entry(self, entry: AuthorizationScopeEntry) -> None:
        self._require_draft()
        self._scope.discard(entry)
        self._touch()

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def submit_for_approval(self) -> None:
        """DRAFT -> PENDING_APPROVAL.

        Raises:
            InvalidAuthorizationTransitionError: If not DRAFT.
            EmptyAuthorizationScopeError: If missing scope or action
                classes.
        """
        if self._status != AuthorizationStatus.DRAFT:
            raise InvalidAuthorizationTransitionError(str(self._status), "pending_approval")
        if not self._scope or not self._action_classes:
            raise EmptyAuthorizationScopeError(str(self._id))
        self._status = AuthorizationStatus.PENDING_APPROVAL
        self._touch()
        self._record_event(
            AuthorizationSubmittedForApproval(
                occurred_at=_now(),
                authorization_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def approve(self, approver_user_id: EntityId) -> None:
        """PENDING_APPROVAL -> ACTIVE.

        Raises:
            InvalidAuthorizationTransitionError: If not PENDING_APPROVAL.
            SelfApprovalForbiddenError: If approver_user_id is the
                requester. Unconditional — checked here, at the
                aggregate itself, in addition to the application-layer
                permission check, so it can never be bypassed by any
                caller of this method regardless of role.
        """
        if self._status != AuthorizationStatus.PENDING_APPROVAL:
            raise InvalidAuthorizationTransitionError(str(self._status), "active")
        if approver_user_id == self._requester_user_id:
            raise SelfApprovalForbiddenError(str(self._id))
        self._status = AuthorizationStatus.ACTIVE
        self._touch()
        self._record_event(
            AuthorizationApproved(
                occurred_at=_now(),
                authorization_id=str(self._id),
                organization_id=str(self._organization_id),
                approver_user_id=str(approver_user_id),
            )
        )

    def reject(self, approver_user_id: EntityId, reason: str = "") -> None:
        """PENDING_APPROVAL -> REJECTED. Terminal.

        Raises:
            InvalidAuthorizationTransitionError: If not PENDING_APPROVAL.
            SelfApprovalForbiddenError: If approver_user_id is the
                requester (a requester withdraws by leaving it pending,
                or an admin revokes-in-spirit by rejecting; the
                requester cannot decide their own request either way).
        """
        if self._status != AuthorizationStatus.PENDING_APPROVAL:
            raise InvalidAuthorizationTransitionError(str(self._status), "rejected")
        if approver_user_id == self._requester_user_id:
            raise SelfApprovalForbiddenError(str(self._id))
        self._status = AuthorizationStatus.REJECTED
        self._touch()
        self._record_event(
            AuthorizationRejected(
                occurred_at=_now(),
                authorization_id=str(self._id),
                organization_id=str(self._organization_id),
                approver_user_id=str(approver_user_id),
                reason=reason,
            )
        )

    def revoke(self, revoked_by_user_id: EntityId, reason: str = "") -> None:
        """ACTIVE -> REVOKED. Terminal.

        Raises:
            InvalidAuthorizationTransitionError: If not ACTIVE.
        """
        if self._status != AuthorizationStatus.ACTIVE:
            raise InvalidAuthorizationTransitionError(str(self._status), "revoked")
        self._status = AuthorizationStatus.REVOKED
        self._touch()
        self._record_event(
            AuthorizationRevoked(
                occurred_at=_now(),
                authorization_id=str(self._id),
                organization_id=str(self._organization_id),
                revoked_by_user_id=str(revoked_by_user_id),
                reason=reason,
            )
        )

    def mark_expired(self) -> None:
        """ACTIVE -> EXPIRED. Idempotent: a no-op if already EXPIRED (a
        lazy, read-time materialization racing a background sweep must
        not raise). Still raises for any other non-ACTIVE status — an
        authorization that never became ACTIVE cannot "expire".

        Time-of-use enforcement does NOT depend on this method having
        been called — ExecutionPolicyService always recomputes
        is_active_now(now) itself. This method exists only so the
        persisted status can be brought in line with reality for
        listing/reporting purposes.
        """
        if self._status == AuthorizationStatus.EXPIRED:
            return
        if self._status != AuthorizationStatus.ACTIVE:
            raise InvalidAuthorizationTransitionError(str(self._status), "expired")

        self._status = AuthorizationStatus.EXPIRED
        self._touch()
        self._record_event(
            AuthorizationExpired(
                occurred_at=_now(),
                authorization_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[AuthorizationEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_draft(self) -> None:
        if self._status != AuthorizationStatus.DRAFT:
            raise InvalidAuthorizationTransitionError(str(self._status), "draft-mutation")

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: AuthorizationEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecurityAuthorization):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"SecurityAuthorization(id={self._id}, org={self._organization_id}, "
            f"status={self._status})"
        )


class AuthorizationApproval:
    """A single, immutable-once-decided approval request/decision for one
    SecurityAuthorization. Created when the authorization is submitted
    for approval; decided exactly once thereafter."""

    __slots__ = (
        "_approver_user_id",
        "_authorization_id",
        "_decided_at",
        "_decision",
        "_id",
        "_organization_id",
        "_reason",
        "_requested_at",
        "_requester_user_id",
    )

    def __init__(
        self,
        id: EntityId,
        authorization_id: EntityId,
        organization_id: EntityId,
        requester_user_id: EntityId,
        requested_at: datetime,
        approver_user_id: EntityId | None = None,
        decision: ApprovalDecision | None = None,
        decided_at: datetime | None = None,
        reason: str = "",
    ) -> None:
        self._id = id
        self._authorization_id = authorization_id
        self._organization_id = organization_id
        self._requester_user_id = requester_user_id
        self._requested_at = requested_at
        self._approver_user_id = approver_user_id
        self._decision = decision
        self._decided_at = decided_at
        self._reason = reason

    @classmethod
    def create(
        cls,
        authorization_id: EntityId,
        organization_id: EntityId,
        requester_user_id: EntityId,
    ) -> Self:
        return cls(
            id=EntityId.generate(),
            authorization_id=authorization_id,
            organization_id=organization_id,
            requester_user_id=requester_user_id,
            requested_at=_now(),
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def authorization_id(self) -> EntityId:
        return self._authorization_id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def requester_user_id(self) -> EntityId:
        return self._requester_user_id

    @property
    def requested_at(self) -> datetime:
        return self._requested_at

    @property
    def approver_user_id(self) -> EntityId | None:
        return self._approver_user_id

    @property
    def decision(self) -> ApprovalDecision | None:
        return self._decision

    @property
    def decided_at(self) -> datetime | None:
        return self._decided_at

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def is_decided(self) -> bool:
        return self._decision is not None

    def decide(
        self, approver_user_id: EntityId, decision: ApprovalDecision, reason: str = ""
    ) -> None:
        """Record the terminal decision.

        Raises:
            SelfApprovalForbiddenError: If approver_user_id is the
                requester.
            ApprovalAlreadyDecidedError: If this approval has already
                been decided — approval history is immutable, never
                overwritten in place. This is also what the loser of a
                concurrent approve()/reject() race observes (see
                SqlAlchemyAuthorizationApprovalRepository.get_by_authorization_id_for_update).
        """
        if approver_user_id == self._requester_user_id:
            raise SelfApprovalForbiddenError(str(self._authorization_id))
        if self.is_decided:
            raise ApprovalAlreadyDecidedError(str(self._id), str(self._decision))
        self._approver_user_id = approver_user_id
        self._decision = decision
        self._decided_at = _now()
        self._reason = reason

    def __repr__(self) -> str:
        return (
            f"AuthorizationApproval(id={self._id}, authorization={self._authorization_id}, "
            f"decision={self._decision})"
        )
