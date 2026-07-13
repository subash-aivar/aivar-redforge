"""Execution Plan aggregate root.

An Execution Plan is the runtime representation of a Validation Policy.
It holds the ordered stages and steps that the engine dispatches to
Provider Adapters. The plan tracks progress and handles failures.

The Execution Engine generates plans from policies. Provider Adapters
execute individual steps. The Evidence Engine stores results.
"""

from typing import Self

from redforge.domain.execution.events import (
    ExecutionEvent,
    PlanCancelled,
    PlanCompleted,
    PlanCreated,
    PlanFailed,
    PlanStarted,
    StepCompleted,
    _now,
)
from redforge.domain.execution.exceptions import (
    InvalidPlanTransitionError,
    PlanAlreadyTerminalError,
    PlanEmptyError,
)
from redforge.domain.execution.value_objects import (
    ExecutionStage,
    ExecutionStep,
    FailureStrategy,
    PlanStatus,
    RetryPolicy,
    StepResult,
    StepStatus,
    TimeoutPolicy,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class ExecutionPlan:
    """Execution Plan aggregate root.

    Invariants:
    - Always linked to a ValidationRun and Policy.
    - Must have at least one stage to start.
    - Terminal states (COMPLETED, FAILED, CANCELLED, TIMED_OUT) are immutable.
    - Steps are completed one at a time via record_step_result.
    - Failure strategy determines whether plan continues after step failure.
    """

    __slots__ = (
        "_events",
        "_failure_reason",
        "_failure_strategy",
        "_id",
        "_policy_id",
        "_retry_policy",
        "_run_id",
        "_stages",
        "_status",
        "_target_id",
        "_timeout_policy",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        run_id: EntityId,
        policy_id: EntityId,
        target_id: EntityId,
        stages: list[ExecutionStage],
        status: PlanStatus,
        failure_strategy: FailureStrategy,
        retry_policy: RetryPolicy,
        timeout_policy: TimeoutPolicy,
        failure_reason: str | None,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._run_id = run_id
        self._policy_id = policy_id
        self._target_id = target_id
        self._stages = stages
        self._status = status
        self._failure_strategy = failure_strategy
        self._retry_policy = retry_policy
        self._timeout_policy = timeout_policy
        self._failure_reason = failure_reason
        self._timestamps = timestamps
        self._events: list[ExecutionEvent] = []

    @classmethod
    def create(
        cls,
        run_id: EntityId,
        policy_id: EntityId,
        target_id: EntityId,
        stages: list[ExecutionStage],
        failure_strategy: FailureStrategy = FailureStrategy.CONTINUE,
        retry_policy: RetryPolicy | None = None,
        timeout_policy: TimeoutPolicy | None = None,
    ) -> Self:
        """Create an execution plan from resolved stages."""
        plan = cls(
            id=EntityId.generate(),
            run_id=run_id,
            policy_id=policy_id,
            target_id=target_id,
            stages=list(stages),
            status=PlanStatus.PENDING,
            failure_strategy=failure_strategy,
            retry_policy=retry_policy or RetryPolicy(),
            timeout_policy=timeout_policy or TimeoutPolicy(),
            failure_reason=None,
            timestamps=AuditTimestamps.create(),
        )
        plan._record_event(
            PlanCreated(
                occurred_at=_now(),
                plan_id=str(plan._id),
                run_id=str(run_id),
                policy_id=str(policy_id),
                stage_count=len(stages),
                total_steps=plan.total_steps,
            )
        )
        return plan

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def run_id(self) -> EntityId:
        return self._run_id

    @property
    def policy_id(self) -> EntityId:
        return self._policy_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def stages(self) -> tuple[ExecutionStage, ...]:
        return tuple(self._stages)

    @property
    def status(self) -> PlanStatus:
        return self._status

    @property
    def failure_strategy(self) -> FailureStrategy:
        return self._failure_strategy

    @property
    def retry_policy(self) -> RetryPolicy:
        return self._retry_policy

    @property
    def timeout_policy(self) -> TimeoutPolicy:
        return self._timeout_policy

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_terminal(self) -> bool:
        return self._status in {
            PlanStatus.COMPLETED,
            PlanStatus.FAILED,
            PlanStatus.CANCELLED,
            PlanStatus.TIMED_OUT,
        }

    @property
    def total_steps(self) -> int:
        return sum(s.step_count for s in self._stages)

    @property
    def completed_steps(self) -> int:
        return sum(
            1
            for stage in self._stages
            for step in stage.steps
            if step.status == StepStatus.COMPLETED
        )

    @property
    def failed_steps(self) -> int:
        return sum(
            1
            for stage in self._stages
            for step in stage.steps
            if step.status == StepStatus.FAILED
        )

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Begin execution of the plan.

        Transitions: PENDING → RUNNING
        """
        if self._status != PlanStatus.PENDING:
            raise InvalidPlanTransitionError(str(self._status), "running")
        if not self._stages:
            raise PlanEmptyError(str(self._id))
        self._status = PlanStatus.RUNNING
        self._touch()
        self._record_event(
            PlanStarted(occurred_at=_now(), plan_id=str(self._id))
        )

    def complete(self) -> None:
        """Mark the plan as successfully completed.

        Transitions: RUNNING → COMPLETED
        """
        self._require_running()
        self._status = PlanStatus.COMPLETED
        self._touch()
        self._record_event(
            PlanCompleted(
                occurred_at=_now(),
                plan_id=str(self._id),
                steps_completed=self.completed_steps,
                steps_failed=self.failed_steps,
            )
        )

    def fail(self, reason: str) -> None:
        """Mark the plan as failed.

        Transitions: PENDING → FAILED, RUNNING → FAILED
        """
        if self.is_terminal:
            raise PlanAlreadyTerminalError(str(self._id))
        self._status = PlanStatus.FAILED
        self._failure_reason = reason
        self._touch()
        self._record_event(
            PlanFailed(
                occurred_at=_now(), plan_id=str(self._id), reason=reason
            )
        )

    def cancel(self) -> None:
        """Cancel the plan.

        Transitions: PENDING → CANCELLED, RUNNING → CANCELLED
        """
        if self.is_terminal:
            raise PlanAlreadyTerminalError(str(self._id))
        self._status = PlanStatus.CANCELLED
        self._touch()
        self._record_event(
            PlanCancelled(occurred_at=_now(), plan_id=str(self._id))
        )

    def timeout(self) -> None:
        """Mark the plan as timed out.

        Transitions: RUNNING → TIMED_OUT
        """
        self._require_running()
        self._status = PlanStatus.TIMED_OUT
        self._failure_reason = "Plan execution exceeded timeout"
        self._touch()

    def record_step_result(self, step_id: str, result: StepResult) -> None:
        """Record the outcome of an executed step.

        Updates the step status within its stage. If failure_strategy
        is FAIL_FAST and the step failed, the plan fails immediately.
        """
        self._require_running()
        self._update_step(step_id, result)
        self._touch()
        self._record_event(
            StepCompleted(
                occurred_at=_now(),
                plan_id=str(self._id),
                step_id=step_id,
                status=str(result.status),
                evidence_id=result.evidence_id,
            )
        )

        if (
            result.status == StepStatus.FAILED
            and self._failure_strategy == FailureStrategy.FAIL_FAST
        ):
            self.fail(f"Step '{step_id}' failed: {result.error_message}")

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[ExecutionEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_running(self) -> None:
        if self._status != PlanStatus.RUNNING:
            raise InvalidPlanTransitionError(str(self._status), "requires running")

    def _update_step(self, step_id: str, result: StepResult) -> None:
        """Replace the step with an updated version containing the result."""
        for i, stage in enumerate(self._stages):
            for j, step in enumerate(stage.steps):
                if step.step_id == step_id:
                    updated = ExecutionStep(
                        step_id=step.step_id,
                        attack_id=step.attack_id,
                        target_id=step.target_id,
                        order=step.order,
                        status=result.status,
                        result=result,
                    )
                    steps = list(stage.steps)
                    steps[j] = updated
                    self._stages[i] = ExecutionStage(
                        stage_id=stage.stage_id,
                        name=stage.name,
                        mode=stage.mode,
                        steps=tuple(steps),
                        order=stage.order,
                    )
                    return

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: ExecutionEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExecutionPlan):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"ExecutionPlan(id={self._id}, status={self._status}, "
            f"stages={len(self._stages)}, steps={self.total_steps})"
        )
