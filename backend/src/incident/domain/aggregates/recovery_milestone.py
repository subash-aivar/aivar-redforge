"""RecoveryMilestone aggregate."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from incident.domain.events.incident_events import RecoveryMilestoneCompleted
from incident.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    InvalidPhaseTransition,
    TenantMismatch,
)
from incident.domain.value_objects.enums import RecoveryMilestoneStatus
from incident.domain.value_objects.identifiers import (
    IncidentId,
    RecoveryMilestoneId,
    TenantId,
)


class RecoveryMilestone:
    __slots__ = (
        "_pending_events",
        "completed_at",
        "completion_notes",
        "defer_reason",
        "description",
        "incident_id",
        "milestone_id",
        "owner",
        "started_at",
        "status",
        "target_date",
        "tenant_id",
        "title",
    )

    def __init__(
        self,
        milestone_id: RecoveryMilestoneId,
        tenant_id: TenantId,
        incident_id: IncidentId,
        title: str,
        description: str,
        owner: str,
        target_date: datetime,
        status: RecoveryMilestoneStatus,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        completion_notes: str | None = None,
        defer_reason: str | None = None,
    ) -> None:
        self.milestone_id = milestone_id
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.title = title
        self.description = description
        self.owner = owner
        self.target_date = target_date
        self.status = status
        self.started_at = started_at
        self.completed_at = completed_at
        self.completion_notes = completion_notes
        self.defer_reason = defer_reason
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        ev = list(self._pending_events)
        self._pending_events.clear()
        return ev

    @classmethod
    def create(
        cls,
        milestone_id: RecoveryMilestoneId,
        tenant_id: TenantId,
        incident_id: IncidentId,
        title: str,
        description: str,
        owner: str,
        target_date: datetime,
    ) -> RecoveryMilestone:
        return cls(
            milestone_id,
            tenant_id,
            incident_id,
            title,
            description,
            owner,
            target_date,
            RecoveryMilestoneStatus.PENDING,
        )

    def start(self, tenant_id: TenantId, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != RecoveryMilestoneStatus.PENDING:
            raise InvalidPhaseTransition()
        self.status = RecoveryMilestoneStatus.IN_PROGRESS
        self.started_at = at

    def complete(self, tenant_id: TenantId, notes: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status not in {
            RecoveryMilestoneStatus.PENDING,
            RecoveryMilestoneStatus.IN_PROGRESS,
        }:
            raise InvalidPhaseTransition()
        self.status = RecoveryMilestoneStatus.COMPLETED
        self.completion_notes = notes
        self.completed_at = at
        self._pending_events.append(
            RecoveryMilestoneCompleted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.milestone_id),
                milestone_id=str(self.milestone_id),
                incident_id=str(self.incident_id),
                completed_at=at.isoformat(),
            )
        )

    def defer(self, tenant_id: TenantId, reason: str) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if not reason.strip():
            raise DomainInvariantViolation("DEFERRED requires reason")
        self.status = RecoveryMilestoneStatus.DEFERRED
        self.defer_reason = reason
