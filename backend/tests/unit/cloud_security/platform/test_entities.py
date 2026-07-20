"""Entity lifecycle tests for OrchestrationRun."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from ulid import ULID

from redforge.domain.cloud_security.platform.entities import (
    OrchestrationRun,
    OrchestrationStepResult,
)
from redforge.domain.cloud_security.platform.events import (
    PlatformOrchestrationCompleted,
    PlatformOrchestrationStarted,
    PlatformOrchestrationStepFailed,
)
from redforge.domain.cloud_security.platform.exceptions import InvalidPlatformArgumentError
from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationScope,
    RunStatus,
    StepName,
    StepStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId

ORG = OrganizationId(str(ULID()))
NOW = datetime(2026, 7, 20, 9, 0, tzinfo=UTC)


def _start(**kwargs: object) -> OrchestrationRun:
    defaults: dict[str, object] = {
        "organization_id": ORG,
        "scope": OrchestrationScope.ACCOUNT,
        "target_id": "acct-1",
        "operation_id": "op_test",
        "now": NOW,
    }
    defaults.update(kwargs)
    return OrchestrationRun.start(**defaults)  # type: ignore[arg-type]


def test_start_emits_started_event() -> None:
    run = _start()
    assert run.status is RunStatus.RUNNING
    events = run.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], PlatformOrchestrationStarted)
    assert events[0].operation_id == "op_test"


def test_start_requires_target() -> None:
    with pytest.raises(InvalidPlatformArgumentError):
        _start(target_id="  ")


def test_start_requires_operation_id() -> None:
    with pytest.raises(InvalidPlatformArgumentError):
        _start(operation_id="")


@pytest.mark.parametrize("step", list(StepName))
def test_fail_step_records_and_emits(step: StepName) -> None:
    run = _start()
    run.pop_events()
    result = run.fail_step(step, "boom", now=NOW)
    assert result.status is StepStatus.FAILED
    assert result.error == "boom"
    events = run.pop_events()
    assert any(isinstance(e, PlatformOrchestrationStepFailed) for e in events)


@pytest.mark.parametrize(
    ("failed", "completed", "expected"),
    [
        (0, 3, RunStatus.COMPLETED),
        (1, 2, RunStatus.PARTIAL),
        (2, 0, RunStatus.FAILED),
    ],
)
def test_complete_status_rollup(
    failed: int, completed: int, expected: RunStatus
) -> None:
    run = _start()
    run.pop_events()
    for i in range(completed):
        run.record_step(
            OrchestrationStepResult(
                step_name=StepName.DISCOVER_ASSETS,
                status=StepStatus.COMPLETED,
                message=f"ok-{i}",
            )
        )
    for i in range(failed):
        run.fail_step(StepName.EVALUATE_CSPM, f"err-{i}", now=NOW)
    run.pop_events()
    run.complete(now=NOW)
    assert run.status is expected
    events = run.pop_events()
    assert isinstance(events[-1], PlatformOrchestrationCompleted)


def test_mark_partial() -> None:
    run = _start()
    run.pop_events()
    run.mark_partial(diagnostics={"note": "partial"}, now=NOW)
    assert run.status is RunStatus.PARTIAL
    assert run.diagnostics["note"] == "partial"


def test_fail_sets_fatal() -> None:
    run = _start()
    run.pop_events()
    run.fail("fatal", now=NOW)
    assert run.status is RunStatus.FAILED
    assert "fatal" in str(run.diagnostics.get("fatal_error"))


def test_step_result_roundtrip_dict() -> None:
    step = OrchestrationStepResult(
        step_name=StepName.CALCULATE_RISK,
        status=StepStatus.COMPLETED,
        started_at=NOW,
        completed_at=NOW,
        duration_ms=12.5,
        message="ok",
        details={"n": 1},
    )
    restored = OrchestrationStepResult.from_dict(step.to_dict())
    assert restored.step_name is StepName.CALCULATE_RISK
    assert restored.duration_ms == 12.5
    assert restored.details["n"] == 1


@pytest.mark.parametrize("scope", list(OrchestrationScope))
def test_start_scopes(scope: OrchestrationScope) -> None:
    run = _start(scope=scope, target_id="t")
    assert run.scope is scope


@pytest.mark.parametrize("status", list(StepStatus))
def test_record_step_all_statuses(status: StepStatus) -> None:
    run = _start()
    run.record_step(
        OrchestrationStepResult(step_name=StepName.VALIDATE, status=status, message="m")
    )
    assert run.steps[-1].status is status
