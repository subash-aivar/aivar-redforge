"""AttackAction aggregate — immutable forensic record of a technique execution."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from execution.domain.events.pipeline_events import (
    AttackActionAborted,
    AttackActionAuthorized,
    AttackActionCompleted,
    AttackActionFailed,
    AttackActionStarted,
    AttackActionTamperDetected,
    AttackActionTimedOut,
)
from execution.domain.exceptions.domain_exceptions import (
    AggregateSealed,
    AuthorizationRequired,
    InvalidStateTransition,
    TenantMismatch,
)
from execution.domain.value_objects.enums import AttackActionState
from execution.domain.value_objects.execution_vos import (
    ActionHash,
    ActionInput,
    ActionOutputRef,
    AuthorizationToken,
    is_terminal_action_state,
)
from execution.domain.value_objects.identifiers import AttackActionId

if TYPE_CHECKING:
    from datetime import datetime

    from execution.domain.events.base import BaseDomainEvent
    from execution.domain.value_objects.execution_vos import (
        ExecutionStepRef,
        OperatorRef,
        SafetyCheckResult,
        TargetRef,
        TechniqueRef,
        WorkerRef,
    )
    from execution.domain.value_objects.identifiers import (
        EngagementId,
        OperationId,
        TenantId,
    )

_ALLOWED: dict[AttackActionState, frozenset[AttackActionState]] = {
    AttackActionState.AUTHORIZED: frozenset(
        {
            AttackActionState.EXECUTING,
            AttackActionState.ABORTED,
            AttackActionState.FAILED,
        }
    ),
    AttackActionState.EXECUTING: frozenset(
        {
            AttackActionState.COMPLETED,
            AttackActionState.FAILED,
            AttackActionState.ABORTED,
            AttackActionState.TIMED_OUT,
        }
    ),
    AttackActionState.COMPLETED: frozenset(),
    AttackActionState.FAILED: frozenset(),
    AttackActionState.ABORTED: frozenset(),
    AttackActionState.TIMED_OUT: frozenset(),
}


class AttackAction:
    """Created only via factory requiring AuthorizationToken (ADR-M29-001)."""

    __slots__ = (
        "_pending_events",
        "_version",
        "action_hash",
        "action_id",
        "action_input",
        "completion_timestamp",
        "created_at",
        "engagement_id",
        "execution_timestamp",
        "failure_reason",
        "input_hash",
        "operation_id",
        "operator_ref",
        "output_ref",
        "safety_check",
        "state",
        "step_ref",
        "target_ref",
        "technique_ref",
        "tenant_id",
        "updated_at",
        "worker_ref",
    )

    def __init__(
        self,
        action_id: AttackActionId,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        operation_id: OperationId,
        step_ref: ExecutionStepRef,
        target_ref: TargetRef,
        technique_ref: TechniqueRef,
        operator_ref: OperatorRef,
        worker_ref: WorkerRef | None,
        action_input: ActionInput,
        input_hash: str,
        action_hash: ActionHash,
        state: AttackActionState,
        safety_check: SafetyCheckResult,
        execution_timestamp: datetime,
        created_at: datetime,
        updated_at: datetime,
        version: int,
        completion_timestamp: datetime | None = None,
        output_ref: ActionOutputRef | None = None,
        failure_reason: str | None = None,
    ) -> None:
        self.action_id = action_id
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id
        self.operation_id = operation_id
        self.step_ref = step_ref
        self.target_ref = target_ref
        self.technique_ref = technique_ref
        self.operator_ref = operator_ref
        self.worker_ref = worker_ref
        self.action_input = action_input
        self.input_hash = input_hash
        self.action_hash = action_hash
        self.state = state
        self.safety_check = safety_check
        self.execution_timestamp = execution_timestamp
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self.completion_timestamp = completion_timestamp
        self.output_ref = output_ref
        self.failure_reason = failure_reason
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> AttackActionId:
        return self.action_id

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_not_sealed(self) -> None:
        if is_terminal_action_state(self.state):
            raise AggregateSealed(str(self.action_id), self.state.value)

    def _transition(self, to_state: AttackActionState) -> None:
        self._assert_not_sealed()
        allowed = _ALLOWED.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.action_id),
            )
        self.state = to_state

    @classmethod
    def create_authorized(
        cls,
        token: AuthorizationToken,
        action_input: ActionInput,
        now: datetime,
    ) -> AttackAction:
        if token is None:
            raise AuthorizationRequired()
        if token.safety.kill_switch_state.value != "Armed":
            raise AuthorizationRequired("Kill switch was not Armed at authorization")
        if token.safety.scope_status.value != "Verified":
            raise AuthorizationRequired("Scope was not Verified at authorization")
        if token.safety.rate_limit_decision.value != "Permitted":
            raise AuthorizationRequired("Rate limit was not Permitted at authorization")
        if not token.safety.window_permitted:
            raise AuthorizationRequired("Execution window not permitted")
        if not token.safety.worker_capability_ok:
            raise AuthorizationRequired("Worker capability check failed")

        action_id = AttackActionId.generate()
        input_hash = action_input.input_hash()
        action_hash = ActionHash.compute(
            action_id,
            token.target_ref,
            token.technique_ref,
            input_hash,
            now,
        )
        action = cls(
            action_id=action_id,
            tenant_id=token.tenant_id,
            engagement_id=token.engagement_id,
            operation_id=token.operation_id,
            step_ref=token.step_ref,
            target_ref=token.target_ref,
            technique_ref=token.technique_ref,
            operator_ref=token.operator_ref,
            worker_ref=token.worker_ref,
            action_input=action_input,
            input_hash=input_hash,
            action_hash=action_hash,
            state=AttackActionState.AUTHORIZED,
            safety_check=token.safety,
            execution_timestamp=now,
            created_at=now,
            updated_at=now,
            version=0,
        )
        action._emit(
            AttackActionAuthorized(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=token.tenant_id,
                aggregate_id=str(action_id),
                aggregate_type="AttackAction",
                engagement_id=str(token.engagement_id),
                operation_id=str(token.operation_id),
                step_id=str(token.step_ref.step_id),
                target_id=str(token.target_ref.target_id),
                technique_id=token.technique_ref.technique_id,
                operator_id=str(token.operator_ref.operator_id),
                action_hash=action_hash.value,
            )
        )
        return action

    def start(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(AttackActionState.EXECUTING)
        self._mutate(now)
        self._emit(
            AttackActionStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.action_id),
                aggregate_type="AttackAction",
                engagement_id=str(self.engagement_id),
                operation_id=str(self.operation_id),
                worker_id=str(self.worker_ref.worker_id) if self.worker_ref else None,
                execution_timestamp=self.execution_timestamp,
            )
        )

    def complete(
        self,
        tenant_id: TenantId,
        now: datetime,
        output_ref: ActionOutputRef | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._transition(AttackActionState.COMPLETED)
        self.completion_timestamp = now
        if output_ref is not None:
            self.output_ref = output_ref
        self._mutate(now)
        self._emit(
            AttackActionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.action_id),
                aggregate_type="AttackAction",
                engagement_id=str(self.engagement_id),
                operation_id=str(self.operation_id),
                completion_timestamp=now,
                output_hash=output_ref.output_hash if output_ref else None,
            )
        )

    def fail(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(AttackActionState.FAILED)
        self.completion_timestamp = now
        self.failure_reason = reason
        self._mutate(now)
        self._emit(
            AttackActionFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.action_id),
                aggregate_type="AttackAction",
                engagement_id=str(self.engagement_id),
                operation_id=str(self.operation_id),
                failure_reason=reason,
                completion_timestamp=now,
            )
        )

    def abort(
        self,
        tenant_id: TenantId,
        reason: str,
        authority_ref: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._transition(AttackActionState.ABORTED)
        self.completion_timestamp = now
        self.failure_reason = reason
        self._mutate(now)
        self._emit(
            AttackActionAborted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.action_id),
                aggregate_type="AttackAction",
                engagement_id=str(self.engagement_id),
                operation_id=str(self.operation_id),
                abort_reason=reason,
                authority_ref=authority_ref,
                completion_timestamp=now,
            )
        )

    def mark_timed_out(
        self,
        tenant_id: TenantId,
        max_duration_seconds: int,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._transition(AttackActionState.TIMED_OUT)
        self.completion_timestamp = now
        self.failure_reason = f"Timed out after {max_duration_seconds}s"
        self._mutate(now)
        self._emit(
            AttackActionTimedOut(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.action_id),
                aggregate_type="AttackAction",
                engagement_id=str(self.engagement_id),
                operation_id=str(self.operation_id),
                completion_timestamp=now,
                max_duration_seconds=max_duration_seconds,
            )
        )

    def record_output_ref(
        self,
        tenant_id: TenantId,
        output_ref: ActionOutputRef,
        now: datetime,
    ) -> None:
        """Store hash + storage_ref only — no evidence blob (Phase 5)."""
        self._assert_tenant(tenant_id)
        if is_terminal_action_state(self.state) and self.state != AttackActionState.COMPLETED:
            raise AggregateSealed(str(self.action_id), self.state.value)
        self.output_ref = output_ref
        self._mutate(now)

    def verify_integrity(self, now: datetime) -> bool:
        expected = ActionHash.compute(
            self.action_id,
            self.target_ref,
            self.technique_ref,
            self.input_hash,
            self.execution_timestamp,
        )
        if expected.value != self.action_hash.value:
            self._emit(
                AttackActionTamperDetected(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.action_id),
                    aggregate_type="AttackAction",
                    engagement_id=str(self.engagement_id),
                    operation_id=str(self.operation_id),
                    expected_hash=expected.value,
                    actual_hash=self.action_hash.value,
                )
            )
            return False
        return True

    def is_terminal(self) -> bool:
        return is_terminal_action_state(self.state)
