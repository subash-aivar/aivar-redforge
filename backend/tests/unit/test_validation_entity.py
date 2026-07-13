"""Unit tests for ValidationRun aggregate root."""

import pytest

from redforge.domain.validations.entity import ValidationRun
from redforge.domain.validations.events import (
    ValidationCancelled,
    ValidationCompleted,
    ValidationFailed,
    ValidationRetried,
    ValidationScheduled,
    ValidationStarted,
)
from redforge.domain.validations.exceptions import (
    InvalidValidationTransitionError,
    ValidationAlreadyCompleteError,
)
from redforge.domain.validations.value_objects import (
    TriggerType,
    ValidationStatus,
    ValidationSummary,
)
from redforge.shared.identifiers import EntityId


def _schedule_run(**kwargs) -> ValidationRun:
    defaults = {
        "organization_id": EntityId.generate(),
        "target_id": EntityId.generate(),
        "trigger_type": TriggerType.MANUAL,
    }
    defaults.update(kwargs)
    return ValidationRun.schedule(**defaults)


def _running_run() -> ValidationRun:
    run = _schedule_run()
    run.start()
    run.collect_events()
    return run


class TestSchedule:
    def test_schedule_sets_status(self) -> None:
        run = _schedule_run()
        assert run.status == ValidationStatus.SCHEDULED

    def test_schedule_sets_ids(self) -> None:
        org = EntityId.generate()
        tgt = EntityId.generate()
        run = _schedule_run(organization_id=org, target_id=tgt)
        assert run.organization_id == org
        assert run.target_id == tgt

    def test_schedule_sets_trigger(self) -> None:
        run = _schedule_run(trigger_type=TriggerType.CI_CD)
        assert run.trigger_type == TriggerType.CI_CD

    def test_schedule_no_started_at(self) -> None:
        run = _schedule_run()
        assert run.started_at is None
        assert run.completed_at is None

    def test_schedule_emits_event(self) -> None:
        run = _schedule_run()
        events = run.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], ValidationScheduled)

    def test_schedule_with_policy(self) -> None:
        run = _schedule_run(policy_id="policy-123")
        assert run.policy_id == "policy-123"

    def test_is_not_terminal(self) -> None:
        run = _schedule_run()
        assert run.is_terminal is False


class TestStart:
    def test_start_transitions_to_running(self) -> None:
        run = _schedule_run()
        run.collect_events()
        run.start()
        assert run.status == ValidationStatus.RUNNING

    def test_start_sets_started_at(self) -> None:
        run = _schedule_run()
        run.start()
        assert run.started_at is not None

    def test_start_emits_event(self) -> None:
        run = _schedule_run()
        run.collect_events()
        run.start()
        events = run.collect_events()
        assert isinstance(events[0], ValidationStarted)

    def test_start_already_running_raises(self) -> None:
        run = _running_run()
        with pytest.raises(InvalidValidationTransitionError):
            run.start()


class TestComplete:
    def test_complete_transitions(self) -> None:
        run = _running_run()
        run.complete()
        assert run.status == ValidationStatus.COMPLETED
        assert run.is_terminal is True

    def test_complete_sets_completed_at(self) -> None:
        run = _running_run()
        run.complete()
        assert run.completed_at is not None

    def test_complete_emits_event(self) -> None:
        run = _running_run()
        run.complete()
        events = run.collect_events()
        assert isinstance(events[0], ValidationCompleted)

    def test_complete_with_summary(self) -> None:
        run = _running_run()
        summary = ValidationSummary(
            total_checks=10, passed=8, failed=2, skipped=0, duration_ms=5000
        )
        run.attach_summary(summary)
        run.complete()
        assert run.summary == summary
        events = run.collect_events()
        completed = events[0]
        assert isinstance(completed, ValidationCompleted)
        assert completed.total_checks == 10
        assert completed.failed == 2

    def test_complete_scheduled_raises(self) -> None:
        run = _schedule_run()
        run.collect_events()
        with pytest.raises(InvalidValidationTransitionError):
            run.complete()


class TestFail:
    def test_fail_from_running(self) -> None:
        run = _running_run()
        run.fail("Connection timeout")
        assert run.status == ValidationStatus.FAILED
        assert run.failure_reason == "Connection timeout"
        assert run.completed_at is not None

    def test_fail_from_scheduled(self) -> None:
        run = _schedule_run()
        run.collect_events()
        run.fail("Target unreachable")
        assert run.status == ValidationStatus.FAILED

    def test_fail_emits_event(self) -> None:
        run = _running_run()
        run.fail("Error")
        events = run.collect_events()
        assert isinstance(events[0], ValidationFailed)
        assert events[0].reason == "Error"

    def test_fail_terminal_raises(self) -> None:
        run = _running_run()
        run.complete()
        with pytest.raises(ValidationAlreadyCompleteError):
            run.fail("Late error")


class TestCancel:
    def test_cancel_from_scheduled(self) -> None:
        run = _schedule_run()
        run.collect_events()
        run.cancel()
        assert run.status == ValidationStatus.CANCELLED
        assert run.is_terminal is True

    def test_cancel_from_running(self) -> None:
        run = _running_run()
        run.cancel()
        assert run.status == ValidationStatus.CANCELLED

    def test_cancel_sets_completed_at(self) -> None:
        run = _schedule_run()
        run.cancel()
        assert run.completed_at is not None

    def test_cancel_emits_event(self) -> None:
        run = _schedule_run()
        run.collect_events()
        run.cancel()
        events = run.collect_events()
        assert isinstance(events[0], ValidationCancelled)

    def test_cancel_completed_raises(self) -> None:
        run = _running_run()
        run.complete()
        with pytest.raises(ValidationAlreadyCompleteError):
            run.cancel()


class TestRetry:
    def test_retry_creates_new_run(self) -> None:
        run = _running_run()
        run.fail("Error")
        new_run = run.retry()
        assert new_run.id != run.id
        assert new_run.status == ValidationStatus.SCHEDULED
        assert new_run.target_id == run.target_id

    def test_retry_emits_retried_event(self) -> None:
        run = _running_run()
        run.fail("Error")
        new_run = run.retry()
        events = new_run.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], ValidationRetried)
        assert events[0].original_run_id == str(run.id)

    def test_retry_non_failed_raises(self) -> None:
        run = _running_run()
        with pytest.raises(InvalidValidationTransitionError):
            run.retry()

    def test_retry_preserves_policy(self) -> None:
        run = _schedule_run(policy_id="p1")
        run.start()
        run.fail("x")
        new_run = run.retry()
        assert new_run.policy_id == "p1"


class TestAttachSummary:
    def test_attach_to_running(self) -> None:
        run = _running_run()
        summary = ValidationSummary(
            total_checks=5, passed=5, failed=0, skipped=0, duration_ms=1000
        )
        run.attach_summary(summary)
        assert run.summary == summary

    def test_attach_to_scheduled_raises(self) -> None:
        run = _schedule_run()
        run.collect_events()
        summary = ValidationSummary(
            total_checks=1, passed=1, failed=0, skipped=0, duration_ms=100
        )
        with pytest.raises(InvalidValidationTransitionError):
            run.attach_summary(summary)

    def test_attach_to_completed_raises(self) -> None:
        run = _running_run()
        run.complete()
        summary = ValidationSummary(
            total_checks=1, passed=1, failed=0, skipped=0, duration_ms=100
        )
        with pytest.raises(ValidationAlreadyCompleteError):
            run.attach_summary(summary)


class TestEquality:
    def test_same_id_equal(self) -> None:
        run = _schedule_run()
        run2 = ValidationRun(
            id=run.id,
            organization_id=EntityId.generate(),
            target_id=EntityId.generate(),
            policy_id=None,
            trigger_type=TriggerType.API,
            status=ValidationStatus.RUNNING,
            started_at=None,
            completed_at=None,
            summary=None,
            failure_reason=None,
            timestamps=run.timestamps,
        )
        assert run == run2

    def test_different_id_not_equal(self) -> None:
        assert _schedule_run() != _schedule_run()

    def test_hashable(self) -> None:
        run = _schedule_run()
        assert len({run, run}) == 1
