"""ContainmentAction aggregate."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from incident.domain.events.incident_events import (
    ContainmentActionAuthorized,
    ContainmentActionCompleted,
    ContainmentActionFailed,
    ContainmentActionPendingAuthorization,
    ContainmentAuthorized,
    ContainmentCompleted,
)
from incident.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    InvalidPhaseTransition,
    TenantMismatch,
)
from incident.domain.value_objects.enums import (
    ContainmentActionStatus,
    ContainmentActionType,
    ContainmentAuthorizationLevel,
)
from incident.domain.value_objects.identifiers import (
    ContainmentActionId,
    IncidentId,
    TenantId,
)


class ContainmentAction:
    __slots__ = (
        "_pending_events",
        "action_id",
        "action_type",
        "authorization_level_required",
        "authorized_at",
        "authorized_by",
        "completed_at",
        "description",
        "evidence_ref",
        "executed_by",
        "failure_reason",
        "incident_id",
        "rollback_ref",
        "started_at",
        "status",
        "tenant_id",
    )

    def __init__(
        self,
        action_id: ContainmentActionId,
        tenant_id: TenantId,
        incident_id: IncidentId,
        action_type: ContainmentActionType,
        description: str,
        authorization_level_required: ContainmentAuthorizationLevel,
        status: ContainmentActionStatus,
        *,
        authorized_by: str | None = None,
        authorized_at: datetime | None = None,
        executed_by: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        evidence_ref: str | None = None,
        failure_reason: str | None = None,
        rollback_ref: str | None = None,
    ) -> None:
        self.action_id = action_id
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.action_type = action_type
        self.description = description
        self.authorization_level_required = authorization_level_required
        self.status = status
        self.authorized_by = authorized_by
        self.authorized_at = authorized_at
        self.executed_by = executed_by
        self.started_at = started_at
        self.completed_at = completed_at
        self.evidence_ref = evidence_ref
        self.failure_reason = failure_reason
        self.rollback_ref = rollback_ref
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        ev = list(self._pending_events)
        self._pending_events.clear()
        return ev

    def _emit(self, e: Any) -> None:
        self._pending_events.append(e)

    @classmethod
    def request(
        cls,
        action_id: ContainmentActionId,
        tenant_id: TenantId,
        incident_id: IncidentId,
        action_type: ContainmentActionType,
        description: str,
        level: ContainmentAuthorizationLevel,
    ) -> ContainmentAction:
        action = cls(
            action_id,
            tenant_id,
            incident_id,
            action_type,
            description,
            level,
            ContainmentActionStatus.PENDING_AUTH,
        )
        action._emit(
            ContainmentActionPendingAuthorization(
                tenant_id=str(tenant_id),
                aggregate_id=str(action_id),
                action_id=str(action_id),
                incident_id=str(incident_id),
                action_type=action_type.value,
                authorization_level_required=level.value,
            )
        )
        return action

    def authorize(self, tenant_id: TenantId, authorized_by: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != ContainmentActionStatus.PENDING_AUTH:
            raise InvalidPhaseTransition("authorize only from PENDING_AUTH")
        self.status = ContainmentActionStatus.AUTHORIZED
        self.authorized_by = authorized_by
        self.authorized_at = at
        self._emit(
            ContainmentActionAuthorized(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.action_id),
                action_id=str(self.action_id),
                incident_id=str(self.incident_id),
                authorized_by=authorized_by,
                authorized_at=at.isoformat(),
                action_type=self.action_type.value,
            )
        )
        self._emit(
            ContainmentAuthorized(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.action_id),
                action_id=str(self.action_id),
                incident_id=str(self.incident_id),
                authorized_by=authorized_by,
            )
        )

    def complete(
        self, tenant_id: TenantId, executed_by: str, evidence_ref: str, at: datetime
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status not in {
            ContainmentActionStatus.AUTHORIZED,
            ContainmentActionStatus.EXECUTING,
        }:
            raise InvalidPhaseTransition("complete requires AUTHORIZED/EXECUTING")
        self.status = ContainmentActionStatus.COMPLETED
        self.executed_by = executed_by
        self.evidence_ref = evidence_ref
        self.completed_at = at
        self.started_at = self.started_at or at
        self._emit(
            ContainmentActionCompleted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.action_id),
                action_id=str(self.action_id),
                incident_id=str(self.incident_id),
                completed_at=at.isoformat(),
                evidence_ref=evidence_ref,
            )
        )
        self._emit(
            ContainmentCompleted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.action_id),
                action_id=str(self.action_id),
                incident_id=str(self.incident_id),
            )
        )

    def fail(self, tenant_id: TenantId, reason: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if not reason.strip():
            raise DomainInvariantViolation("failure_reason required")
        self.status = ContainmentActionStatus.FAILED
        self.failure_reason = reason
        self.completed_at = at
        self._emit(
            ContainmentActionFailed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.action_id),
                action_id=str(self.action_id),
                incident_id=str(self.incident_id),
                failure_reason=reason,
            )
        )
