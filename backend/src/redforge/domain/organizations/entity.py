"""Organization aggregate root.

The Organization is the top-level aggregate in RedForge's domain model.
Every resource in the platform (Users, Targets, Validations, Evidence, Findings)
belongs to exactly one Organization.

This entity encapsulates all business rules governing Organization lifecycle
and exposes behavior methods rather than mutable state.
"""

from __future__ import annotations

from redforge.domain.organizations.events import (
    DomainEvent,
    OrganizationActivated,
    OrganizationCreated,
    OrganizationDeactivated,
    OrganizationPlanChanged,
    OrganizationRenamed,
    OrganizationSuspended,
    _now,
)
from redforge.domain.organizations.exceptions import (
    InvalidOrganizationTransitionError,
    OrganizationInactiveError,
)
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
    OrganizationStatus,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class Organization:
    """Organization aggregate root.

    Invariants:
    - An Organization always has a valid name, slug, status, and plan.
    - Status transitions follow defined rules (see _can_transition_to).
    - Only active organizations can be renamed or change plan.
    - Domain events are collected and published after persistence succeeds.
    """

    __slots__ = ("_events", "_id", "_name", "_plan", "_slug", "_status", "_timestamps")

    def __init__(
        self,
        id: EntityId,
        name: OrganizationName,
        slug: OrganizationSlug,
        status: OrganizationStatus,
        plan: OrganizationPlan,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._name = name
        self._slug = slug
        self._status = status
        self._plan = plan
        self._timestamps = timestamps
        self._events: list[DomainEvent] = []

    @classmethod
    def create(
        cls,
        name: OrganizationName,
        slug: OrganizationSlug,
        plan: OrganizationPlan = OrganizationPlan.FREE,
    ) -> Organization:
        """Create a new Organization.

        New organizations start as ACTIVE with the specified plan.
        Emits an OrganizationCreated event.
        """
        org = cls(
            id=EntityId.generate(),
            name=name,
            slug=slug,
            status=OrganizationStatus.ACTIVE,
            plan=plan,
            timestamps=AuditTimestamps.create(),
        )
        org._record_event(
            OrganizationCreated(
                occurred_at=_now(),
                organization_id=str(org._id),
                name=str(org._name),
                slug=str(org._slug),
                plan=str(org._plan),
            )
        )
        return org

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def name(self) -> OrganizationName:
        return self._name

    @property
    def slug(self) -> OrganizationSlug:
        return self._slug

    @property
    def status(self) -> OrganizationStatus:
        return self._status

    @property
    def plan(self) -> OrganizationPlan:
        return self._plan

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_active(self) -> bool:
        return self._status == OrganizationStatus.ACTIVE

    # ─── Behavior ─────────────────────────────────────────────────────────

    def rename(self, new_name: OrganizationName) -> None:
        """Rename the organization.

        Raises:
            OrganizationInactiveError: If the organization is not active.
        """
        self._require_active()
        old_name = self._name
        self._name = new_name
        self._touch()
        self._record_event(
            OrganizationRenamed(
                occurred_at=_now(),
                organization_id=str(self._id),
                old_name=str(old_name),
                new_name=str(new_name),
            )
        )

    def activate(self) -> None:
        """Activate an inactive or suspended organization.

        Raises:
            InvalidOrganizationTransitionError: If already active.
        """
        self._transition_to(OrganizationStatus.ACTIVE)
        self._record_event(
            OrganizationActivated(
                occurred_at=_now(),
                organization_id=str(self._id),
            )
        )

    def deactivate(self) -> None:
        """Deactivate an active organization.

        Raises:
            InvalidOrganizationTransitionError: If not active.
        """
        self._transition_to(OrganizationStatus.INACTIVE)
        self._record_event(
            OrganizationDeactivated(
                occurred_at=_now(),
                organization_id=str(self._id),
            )
        )

    def suspend(self, reason: str = "") -> None:
        """Suspend an active organization (policy violation, billing).

        Distinct from deactivate(): suspension is an involuntary,
        platform-initiated action typically carrying a reason, whereas
        deactivation is organization-initiated self-service.

        Raises:
            InvalidOrganizationTransitionError: If not active.
        """
        self._transition_to(OrganizationStatus.SUSPENDED)
        self._record_event(
            OrganizationSuspended(
                occurred_at=_now(),
                organization_id=str(self._id),
                reason=reason,
            )
        )

    def change_plan(self, new_plan: OrganizationPlan) -> None:
        """Change the organization's subscription plan.

        Raises:
            OrganizationInactiveError: If the organization is not active.
        """
        self._require_active()
        old_plan = self._plan
        if old_plan == new_plan:
            return
        self._plan = new_plan
        self._touch()
        self._record_event(
            OrganizationPlanChanged(
                occurred_at=_now(),
                organization_id=str(self._id),
                old_plan=str(old_plan),
                new_plan=str(new_plan),
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[DomainEvent]:
        """Return and clear all pending domain events.

        Called by the application layer after successful persistence.
        """
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_active(self) -> None:
        """Guard that raises if the organization is not active."""
        if not self.is_active:
            raise OrganizationInactiveError(str(self._id))

    def _transition_to(self, target: OrganizationStatus) -> None:
        """Transition to a new status with validation."""
        if not self._can_transition_to(target):
            raise InvalidOrganizationTransitionError(
                current_status=str(self._status),
                target_status=str(target),
            )
        self._status = target
        self._touch()

    def _can_transition_to(self, target: OrganizationStatus) -> bool:
        """Define valid status transitions.

        ACTIVE -> INACTIVE, SUSPENDED
        INACTIVE -> ACTIVE
        SUSPENDED -> ACTIVE
        """
        valid_transitions: dict[OrganizationStatus, set[OrganizationStatus]] = {
            OrganizationStatus.ACTIVE: {
                OrganizationStatus.INACTIVE,
                OrganizationStatus.SUSPENDED,
            },
            OrganizationStatus.INACTIVE: {OrganizationStatus.ACTIVE},
            OrganizationStatus.SUSPENDED: {OrganizationStatus.ACTIVE},
        }
        return target in valid_transitions.get(self._status, set())

    def _touch(self) -> None:
        """Advance the updated_at timestamp."""
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: DomainEvent) -> None:
        """Add a domain event to the pending events list."""
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Organization):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"Organization(id={self._id}, name={self._name}, status={self._status})"
