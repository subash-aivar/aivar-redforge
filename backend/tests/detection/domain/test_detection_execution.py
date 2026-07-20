"""DetectionExecution aggregate and value object tests."""

from __future__ import annotations

import pytest

from detection.domain.events.execution_events import (
    DetectionExecutionCompleted,
    DetectionExecutionFailed,
    DetectionExecutionScheduled,
    DetectionExecutionStarted,
    DetectionExecutionTimedOut,
)
from detection.domain.exceptions.domain_exceptions import (
    ExecutionLifecycleBlocked,
    InvalidArgument,
    InvalidStateTransition,
)
from detection.domain.value_objects.enums import ExecutionState, ExecutionTrigger
from detection.domain.value_objects.execution_finding import (
    ExecutionError,
    ExecutionStats,
    ExecutionWindow,
)
from tests.detection.phase3_helpers import make_execution


def test_schedule_emits_event(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now)
    events = execution.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], DetectionExecutionScheduled)
    assert execution.state == ExecutionState.SCHEDULED


def test_start_running(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.start(tenant_id=tenant_id, now=now)
    assert execution.state == ExecutionState.RUNNING
    assert isinstance(execution.pop_events()[0], DetectionExecutionStarted)


def test_complete_from_scheduled(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.complete(
        tenant_id=tenant_id,
        stats=ExecutionStats(findings_produced=2, duration_ms=12.5),
        now=now,
    )
    assert execution.state == ExecutionState.COMPLETED
    types = [type(e) for e in execution.pop_events()]
    assert DetectionExecutionStarted in types
    assert DetectionExecutionCompleted in types


def test_record_result(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.record_result(
        tenant_id=tenant_id,
        stats=ExecutionStats(telemetry_records_evaluated=100, findings_produced=1),
        now=now,
    )
    assert execution.state == ExecutionState.COMPLETED
    assert execution.stats.findings_produced == 1


def test_fail(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.fail(
        tenant_id=tenant_id,
        error=ExecutionError(error_type="AdapterError", error_message="timeout"),
        now=now,
    )
    assert execution.state == ExecutionState.FAILED
    assert isinstance(execution.pop_events()[-1], DetectionExecutionFailed)


def test_timeout(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.timeout(tenant_id=tenant_id, duration_ms=5000, now=now)
    assert execution.state == ExecutionState.TIMEDOUT
    assert isinstance(execution.pop_events()[-1], DetectionExecutionTimedOut)


def test_skip(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.skip(tenant_id=tenant_id, reason="rule inactive", now=now)
    assert execution.state == ExecutionState.SKIPPED


def test_cannot_complete_twice(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.record_result(
        tenant_id=tenant_id, stats=ExecutionStats(), now=now
    )
    with pytest.raises((InvalidStateTransition, ExecutionLifecycleBlocked)):
        execution.record_result(
            tenant_id=tenant_id, stats=ExecutionStats(), now=now
        )


def test_cannot_add_finding_to_failed(tenant_id, now) -> None:
    from uuid import uuid4

    from detection.domain.value_objects.identifiers import DetectionFindingId

    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.fail(
        tenant_id=tenant_id,
        error=ExecutionError(error_type="x", error_message="y"),
        now=now,
    )
    with pytest.raises(ExecutionLifecycleBlocked):
        execution.add_finding_ref(
            tenant_id=tenant_id,
            finding_id=DetectionFindingId(uuid4()),
            now=now,
        )


@pytest.mark.parametrize("trigger", list(ExecutionTrigger))
def test_all_triggers(tenant_id, now, trigger: ExecutionTrigger) -> None:
    execution = make_execution(
        tenant_id=tenant_id, now=now, trigger=trigger, pop_events=True
    )
    assert execution.trigger == trigger


def test_execution_window_validation(now) -> None:
    with pytest.raises(InvalidArgument):
        ExecutionWindow(start_time=now, end_time=now)


def test_execution_stats_validation() -> None:
    with pytest.raises(InvalidArgument):
        ExecutionStats(findings_produced=-1)


def test_execution_error_requires_message() -> None:
    with pytest.raises(InvalidArgument):
        ExecutionError(error_type="x", error_message="")


@pytest.mark.parametrize(
    ("from_state", "action"),
    [
        (ExecutionState.COMPLETED, "fail"),
        (ExecutionState.FAILED, "complete"),
        (ExecutionState.TIMEDOUT, "start"),
        (ExecutionState.SKIPPED, "start"),
    ],
)
def test_terminal_blocks(tenant_id, now, from_state, action) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    if from_state == ExecutionState.COMPLETED:
        execution.record_result(tenant_id=tenant_id, stats=ExecutionStats(), now=now)
    elif from_state == ExecutionState.FAILED:
        execution.fail(
            tenant_id=tenant_id,
            error=ExecutionError(error_type="e", error_message="m"),
            now=now,
        )
    elif from_state == ExecutionState.TIMEDOUT:
        execution.timeout(tenant_id=tenant_id, duration_ms=1, now=now)
    else:
        execution.skip(tenant_id=tenant_id, reason="x", now=now)
    execution.pop_events()
    with pytest.raises((InvalidStateTransition, ExecutionLifecycleBlocked)):
        if action == "fail":
            execution.fail(
                tenant_id=tenant_id,
                error=ExecutionError(error_type="e", error_message="m"),
                now=now,
            )
        elif action == "complete":
            execution.record_result(
                tenant_id=tenant_id, stats=ExecutionStats(), now=now
            )
        else:
            execution.start(tenant_id=tenant_id, now=now)
