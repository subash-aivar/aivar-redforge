"""Unit tests for ExecutionPlan aggregate root."""

import pytest

from redforge.domain.execution.entity import ExecutionPlan
from redforge.domain.execution.events import (
    PlanCancelled,
    PlanCompleted,
    PlanCreated,
    PlanFailed,
    PlanStarted,
    StepCompleted,
)
from redforge.domain.execution.exceptions import (
    InvalidPlanTransitionError,
    PlanAlreadyTerminalError,
    PlanEmptyError,
)
from redforge.domain.execution.value_objects import (
    ExecutionMode,
    ExecutionStage,
    ExecutionStep,
    FailureStrategy,
    PlanStatus,
    StepResult,
    StepStatus,
)
from redforge.shared.identifiers import EntityId


def _make_stage(step_count: int = 2) -> ExecutionStage:
    target_id = str(EntityId.generate())
    steps = tuple(
        ExecutionStep(
            step_id=f"step-{i}",
            attack_id=str(EntityId.generate()),
            target_id=target_id,
            order=i,
        )
        for i in range(step_count)
    )
    return ExecutionStage(
        stage_id="stage-0", name="default", mode=ExecutionMode.SEQUENTIAL, steps=steps
    )


def _create_plan(
    failure_strategy: FailureStrategy = FailureStrategy.CONTINUE,
) -> ExecutionPlan:
    return ExecutionPlan.create(
        run_id=EntityId.generate(),
        policy_id=EntityId.generate(),
        target_id=EntityId.generate(),
        stages=[_make_stage()],
        failure_strategy=failure_strategy,
    )


def _running_plan(
    failure_strategy: FailureStrategy = FailureStrategy.CONTINUE,
) -> ExecutionPlan:
    plan = _create_plan(failure_strategy)
    plan.start()
    plan.collect_events()
    return plan


class TestCreate:
    def test_creates_pending(self) -> None:
        plan = _create_plan()
        assert plan.status == PlanStatus.PENDING
        assert plan.is_terminal is False

    def test_sets_ids(self) -> None:
        plan = _create_plan()
        assert plan.run_id is not None
        assert plan.policy_id is not None
        assert plan.target_id is not None

    def test_counts_steps(self) -> None:
        plan = _create_plan()
        assert plan.total_steps == 2
        assert plan.completed_steps == 0

    def test_emits_created_event(self) -> None:
        plan = _create_plan()
        events = plan.collect_events()
        assert isinstance(events[0], PlanCreated)
        assert events[0].total_steps == 2


class TestStart:
    def test_starts(self) -> None:
        plan = _create_plan()
        plan.collect_events()
        plan.start()
        assert plan.status == PlanStatus.RUNNING

    def test_start_emits_event(self) -> None:
        plan = _create_plan()
        plan.collect_events()
        plan.start()
        events = plan.collect_events()
        assert isinstance(events[0], PlanStarted)

    def test_start_already_running_raises(self) -> None:
        plan = _running_plan()
        with pytest.raises(InvalidPlanTransitionError):
            plan.start()

    def test_start_empty_plan_raises(self) -> None:
        plan = ExecutionPlan.create(
            run_id=EntityId.generate(),
            policy_id=EntityId.generate(),
            target_id=EntityId.generate(),
            stages=[],
        )
        plan.collect_events()
        with pytest.raises(PlanEmptyError):
            plan.start()


class TestComplete:
    def test_completes(self) -> None:
        plan = _running_plan()
        plan.complete()
        assert plan.status == PlanStatus.COMPLETED
        assert plan.is_terminal is True

    def test_complete_emits_event(self) -> None:
        plan = _running_plan()
        plan.complete()
        events = plan.collect_events()
        assert isinstance(events[0], PlanCompleted)

    def test_complete_pending_raises(self) -> None:
        plan = _create_plan()
        plan.collect_events()
        with pytest.raises(InvalidPlanTransitionError):
            plan.complete()


class TestFail:
    def test_fails_running(self) -> None:
        plan = _running_plan()
        plan.fail("Target unreachable")
        assert plan.status == PlanStatus.FAILED
        assert plan.failure_reason == "Target unreachable"

    def test_fails_pending(self) -> None:
        plan = _create_plan()
        plan.collect_events()
        plan.fail("Bad config")
        assert plan.status == PlanStatus.FAILED

    def test_fail_terminal_raises(self) -> None:
        plan = _running_plan()
        plan.complete()
        with pytest.raises(PlanAlreadyTerminalError):
            plan.fail("late")

    def test_fail_emits_event(self) -> None:
        plan = _running_plan()
        plan.fail("Error")
        events = plan.collect_events()
        assert isinstance(events[0], PlanFailed)


class TestCancel:
    def test_cancels_running(self) -> None:
        plan = _running_plan()
        plan.cancel()
        assert plan.status == PlanStatus.CANCELLED

    def test_cancels_pending(self) -> None:
        plan = _create_plan()
        plan.collect_events()
        plan.cancel()
        assert plan.status == PlanStatus.CANCELLED

    def test_cancel_terminal_raises(self) -> None:
        plan = _running_plan()
        plan.complete()
        with pytest.raises(PlanAlreadyTerminalError):
            plan.cancel()

    def test_cancel_emits_event(self) -> None:
        plan = _running_plan()
        plan.cancel()
        events = plan.collect_events()
        assert isinstance(events[0], PlanCancelled)


class TestTimeout:
    def test_timeout_running(self) -> None:
        plan = _running_plan()
        plan.timeout()
        assert plan.status == PlanStatus.TIMED_OUT
        assert plan.is_terminal is True

    def test_timeout_pending_raises(self) -> None:
        plan = _create_plan()
        plan.collect_events()
        with pytest.raises(InvalidPlanTransitionError):
            plan.timeout()


class TestRecordStepResult:
    def test_records_success(self) -> None:
        plan = _running_plan()
        result = StepResult(status=StepStatus.COMPLETED, evidence_id="ev-1", duration_ms=100)
        plan.record_step_result("step-0", result)
        assert plan.completed_steps == 1

    def test_emits_step_event(self) -> None:
        plan = _running_plan()
        result = StepResult(status=StepStatus.COMPLETED, evidence_id="ev-1")
        plan.record_step_result("step-0", result)
        events = plan.collect_events()
        assert isinstance(events[0], StepCompleted)
        assert events[0].evidence_id == "ev-1"

    def test_fail_fast_on_failure(self) -> None:
        plan = _running_plan(FailureStrategy.FAIL_FAST)
        result = StepResult(status=StepStatus.FAILED, error_message="boom")
        plan.record_step_result("step-0", result)
        assert plan.status == PlanStatus.FAILED

    def test_continue_on_failure(self) -> None:
        plan = _running_plan(FailureStrategy.CONTINUE)
        result = StepResult(status=StepStatus.FAILED, error_message="boom")
        plan.record_step_result("step-0", result)
        assert plan.status == PlanStatus.RUNNING
        assert plan.failed_steps == 1


class TestEquality:
    def test_same_id_equal(self) -> None:
        plan = _create_plan()
        plan2 = ExecutionPlan(
            id=plan.id, run_id=EntityId.generate(), policy_id=EntityId.generate(),
            target_id=EntityId.generate(), stages=[], status=PlanStatus.COMPLETED,
            failure_strategy=FailureStrategy.FAIL_FAST,
            retry_policy=plan.retry_policy, timeout_policy=plan.timeout_policy,
            failure_reason=None, timestamps=plan.timestamps,
        )
        assert plan == plan2

    def test_different_id_not_equal(self) -> None:
        assert _create_plan() != _create_plan()

    def test_hashable(self) -> None:
        plan = _create_plan()
        assert len({plan, plan}) == 1
