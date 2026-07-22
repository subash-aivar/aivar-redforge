"""AutomationExecution aggregate."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from automated_action.domain.entities.escalation_request import EscalationRequest
from automated_action.domain.events.automation_events import (
    AutomationEscalated,
    AutomationExecutionCompleted,
    AutomationExecutionFailed,
    AutomationExecutionStarted,
)
from automated_action.domain.exceptions.domain_exceptions import (
    InvalidExecutionTransition,
    TenantMismatch,
)
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    EscalationResolution,
    ExecutionStatus,
)
from automated_action.domain.value_objects.identifiers import AutomationExecutionId, TenantId
from automated_action.domain.value_objects.refs import PlaybookRef, TriggerRef


class AutomationExecution:
    __slots__ = (
        "_pending_events",
        "completed_at",
        "current_step",
        "escalation_request",
        "execution_id",
        "failure_reason",
        "max_impact_level",
        "operator_id",
        "playbook_ref",
        "started_at",
        "status",
        "tenant_id",
        "total_steps",
        "trigger_ref",
        "version",
    )

    def __init__(
        self,
        execution_id: AutomationExecutionId,
        tenant_id: TenantId,
        playbook_ref: PlaybookRef,
        trigger_ref: TriggerRef,
        status: ExecutionStatus,
        started_at: datetime,
        operator_id: str,
        current_step: int,
        total_steps: int,
        max_impact_level: ActionImpactLevel,
        *,
        completed_at: datetime | None = None,
        escalation_request: EscalationRequest | None = None,
        failure_reason: str | None = None,
        version: int = 1,
    ) -> None:
        self.execution_id = execution_id
        self.tenant_id = tenant_id
        self.playbook_ref = playbook_ref
        self.trigger_ref = trigger_ref
        self.status = status
        self.started_at = started_at
        self.completed_at = completed_at
        self.operator_id = operator_id
        self.current_step = current_step
        self.total_steps = total_steps
        self.max_impact_level = max_impact_level
        self.escalation_request = escalation_request
        self.failure_reason = failure_reason
        self.version = version
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        playbook_ref: PlaybookRef,
        trigger_ref: TriggerRef,
        operator_id: str,
        total_steps: int,
        max_impact_level: ActionImpactLevel,
    ) -> AutomationExecution:
        now = datetime.now(UTC)
        exe = cls(
            AutomationExecutionId.generate(),
            tenant_id,
            playbook_ref,
            trigger_ref,
            ExecutionStatus.PENDING,
            now,
            operator_id,
            0,
            total_steps,
            max_impact_level,
        )
        return exe

    def start(self) -> None:
        if self.status != ExecutionStatus.PENDING:
            raise InvalidExecutionTransition(self.status.value)
        now = datetime.now(UTC)
        self.status = ExecutionStatus.RUNNING
        self.started_at = now
        self.version += 1
        self._pending_events.append(
            AutomationExecutionStarted(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                playbook_id=self.playbook_ref.playbook_id,
                playbook_version=self.playbook_ref.version_number,
                trigger_source_context=self.trigger_ref.source_context,
                source_event_id=self.trigger_ref.source_event_id,
                total_steps=self.total_steps,
                max_impact_level=self.max_impact_level.value,
                operator_id=self.operator_id,
                started_at=now.isoformat(),
            )
        )

    def escalate(self, step_number: int, impact: ActionImpactLevel, required_role: str) -> None:
        now = datetime.now(UTC)
        timeout = timedelta(minutes=30 if impact == ActionImpactLevel.HIGH else 60)
        esc = EscalationRequest.create(
            step_number, impact, required_role, self.operator_id, now, now + timeout
        )
        self.escalation_request = esc
        self.status = ExecutionStatus.AWAITING_AUTHORIZATION
        self.current_step = step_number
        self.version += 1
        self._pending_events.append(
            AutomationEscalated(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                escalation_id=str(esc.escalation_id),
                step_number=step_number,
                impact_level=impact.value,
                required_role=required_role,
                expires_at=esc.expires_at.isoformat(),
                escalated_at=now.isoformat(),
            )
        )

    def authorize_step(self, escalation_id: str, authorizer_id: str) -> None:
        if self.status != ExecutionStatus.AWAITING_AUTHORIZATION or not self.escalation_request:
            raise InvalidExecutionTransition("not awaiting authorization")
        if str(self.escalation_request.escalation_id) != escalation_id:
            raise InvalidExecutionTransition("escalation mismatch")
        now = datetime.now(UTC)
        self.escalation_request.authorized_by = authorizer_id
        self.escalation_request.authorized_at = now
        self.escalation_request.resolution = EscalationResolution.AUTHORIZED
        self.status = ExecutionStatus.RUNNING
        self.version += 1

    def expire_escalation(self) -> None:
        if not self.escalation_request:
            return
        self.escalation_request.resolution = EscalationResolution.EXPIRED
        self.fail("ESCALATION_TIMEOUT", self.escalation_request.step_number)

    def complete(self, steps_completed: int, steps_failed: int = 0) -> None:
        now = datetime.now(UTC)
        self.status = ExecutionStatus.COMPLETED
        self.completed_at = now
        self.current_step = steps_completed
        self.version += 1
        duration = int((now - self.started_at).total_seconds() * 1000)
        self._pending_events.append(
            AutomationExecutionCompleted(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                playbook_id=self.playbook_ref.playbook_id,
                playbook_version=self.playbook_ref.version_number,
                steps_completed=steps_completed,
                steps_failed=steps_failed,
                completed_at=now.isoformat(),
                duration_ms=duration,
            )
        )

    def fail(self, reason: str, failed_at_step: int | None) -> None:
        now = datetime.now(UTC)
        self.status = ExecutionStatus.FAILED
        self.failure_reason = reason
        self.completed_at = now
        self.version += 1
        self._pending_events.append(
            AutomationExecutionFailed(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                playbook_id=self.playbook_ref.playbook_id,
                failure_reason=reason,
                failed_at_step=failed_at_step,
                failed_at=now.isoformat(),
            )
        )

    def cancel(self, reason: str) -> None:
        self.fail(f"CANCELLED:{reason}", self.current_step)

    def mark_rolled_back(self) -> None:
        self.status = ExecutionStatus.ROLLED_BACK
        self.completed_at = datetime.now(UTC)
        self.version += 1
