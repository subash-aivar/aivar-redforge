"""Unit tests for Continuous Validation Scheduler."""

from datetime import UTC, datetime, timedelta

import pytest

from redforge.application.scheduler import (
    CronTrigger,
    ExecutionLease,
    ExecutionStatus,
    IntervalTrigger,
    ManualTrigger,
    SchedulerService,
    ScheduleStatus,
    ValidationSchedule,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now


class MockPipelineExecutor:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[dict[str, str]] = []
        self._fail = fail

    async def trigger(
        self, organization_id: str, target_id: str, policy_id: str
    ) -> str:
        self.calls.append({
            "org": organization_id, "target": target_id, "policy": policy_id
        })
        if self._fail:
            raise RuntimeError("Pipeline failed")
        return str(EntityId.generate())


def _schedule(
    trigger: CronTrigger | IntervalTrigger | ManualTrigger | None = None,
    status: ScheduleStatus = ScheduleStatus.ACTIVE,
    fire_at: datetime | None = None,
) -> ValidationSchedule:
    s = ValidationSchedule.create(
        organization_id=str(EntityId.generate()),
        target_id=str(EntityId.generate()),
        policy_id=str(EntityId.generate()),
        trigger=trigger or IntervalTrigger(interval_seconds=3600),
    )
    s.status = status
    if fire_at is not None:
        s.next_fire_at = fire_at
    return s


class TestTriggers:
    def test_interval_trigger(self) -> None:
        t = IntervalTrigger(interval_seconds=3600)
        now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert t.next_fire_time(now) == datetime(2025, 1, 1, 13, 0, 0, tzinfo=UTC)

    def test_interval_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            IntervalTrigger(interval_seconds=-1)

    def test_cron_hourly(self) -> None:
        t = CronTrigger(expression="0 * * * *")
        now = datetime(2025, 1, 1, 12, 30, 0, tzinfo=UTC)
        next_time = t.next_fire_time(now)
        assert next_time == datetime(2025, 1, 1, 13, 0, 0, tzinfo=UTC)

    def test_cron_daily(self) -> None:
        t = CronTrigger(expression="0 0 * * *")
        now = datetime(2025, 1, 1, 15, 0, 0, tzinfo=UTC)
        next_time = t.next_fire_time(now)
        assert next_time == datetime(2025, 1, 2, 0, 0, 0, tzinfo=UTC)

    def test_manual_trigger_far_future(self) -> None:
        t = ManualTrigger()
        now = datetime(2025, 1, 1, tzinfo=UTC)
        next_time = t.next_fire_time(now)
        assert (next_time - now).days > 36000


class TestValidationSchedule:
    def test_create(self) -> None:
        s = _schedule()
        assert s.status == ScheduleStatus.ACTIVE
        assert s.next_fire_at is not None

    def test_pause_resume(self) -> None:
        s = _schedule()
        s.pause()
        assert s.status == ScheduleStatus.PAUSED
        assert s.is_due is False
        s.resume()
        assert s.status == ScheduleStatus.ACTIVE

    def test_disable(self) -> None:
        s = _schedule()
        s.disable()
        assert s.status == ScheduleStatus.DISABLED
        assert s.is_due is False

    def test_is_due_past_fire_time(self) -> None:
        past = datetime(2020, 1, 1, tzinfo=UTC)
        s = _schedule(fire_at=past)
        assert s.is_due is True

    def test_is_due_future_fire_time(self) -> None:
        future = datetime(2099, 1, 1, tzinfo=UTC)
        s = _schedule(fire_at=future)
        assert s.is_due is False

    def test_advance_updates_times(self) -> None:
        s = _schedule()
        old_next = s.next_fire_at
        s.advance()
        assert s.last_executed_at is not None
        assert s.next_fire_at != old_next


class TestSchedulerService:
    async def test_evaluates_due_schedules(self) -> None:
        executor = MockPipelineExecutor()
        svc = SchedulerService(executor)
        past = datetime(2020, 1, 1, tzinfo=UTC)
        schedules = [_schedule(fire_at=past), _schedule(fire_at=past)]
        executions = await svc.evaluate(schedules)
        assert len(executions) == 2
        assert len(executor.calls) == 2
        assert all(e.status == ExecutionStatus.COMPLETED for e in executions)

    async def test_skips_non_due(self) -> None:
        executor = MockPipelineExecutor()
        svc = SchedulerService(executor)
        future = datetime(2099, 1, 1, tzinfo=UTC)
        executions = await svc.evaluate([_schedule(fire_at=future)])
        assert len(executions) == 0
        assert len(executor.calls) == 0

    async def test_skips_paused(self) -> None:
        executor = MockPipelineExecutor()
        svc = SchedulerService(executor)
        past = datetime(2020, 1, 1, tzinfo=UTC)
        s = _schedule(fire_at=past, status=ScheduleStatus.PAUSED)
        executions = await svc.evaluate([s])
        assert len(executions) == 0

    async def test_respects_max_parallel(self) -> None:
        executor = MockPipelineExecutor()
        svc = SchedulerService(executor, max_parallel=2)
        past = datetime(2020, 1, 1, tzinfo=UTC)
        schedules = [_schedule(fire_at=past) for _ in range(5)]
        executions = await svc.evaluate(schedules)
        assert len(executions) == 2

    async def test_handles_pipeline_failure(self) -> None:
        executor = MockPipelineExecutor(fail=True)
        svc = SchedulerService(executor)
        past = datetime(2020, 1, 1, tzinfo=UTC)
        executions = await svc.evaluate([_schedule(fire_at=past)])
        assert len(executions) == 1
        assert executions[0].status == ExecutionStatus.FAILED
        assert "Pipeline failed" in executions[0].error_message

    async def test_trigger_manual(self) -> None:
        executor = MockPipelineExecutor()
        svc = SchedulerService(executor)
        s = _schedule(trigger=ManualTrigger())
        execution = await svc.trigger_manual(s)
        assert execution.status == ExecutionStatus.COMPLETED
        assert len(executor.calls) == 1

    async def test_recover_missed(self) -> None:
        executor = MockPipelineExecutor()
        svc = SchedulerService(executor)
        # Missed by 30 minutes
        missed_time = utc_now() - timedelta(minutes=30)
        s = _schedule(fire_at=missed_time)
        s.status = ScheduleStatus.ACTIVE
        executions = await svc.recover_missed([s], window=timedelta(hours=1))
        assert len(executions) == 1

    async def test_recover_ignores_old_missed(self) -> None:
        executor = MockPipelineExecutor()
        svc = SchedulerService(executor)
        # Missed by 3 hours (outside 1 hour window)
        old_missed = utc_now() - timedelta(hours=3)
        s = _schedule(fire_at=old_missed)
        s.status = ScheduleStatus.ACTIVE
        executions = await svc.recover_missed([s], window=timedelta(hours=1))
        assert len(executions) == 0


class TestExecutionLease:
    def test_expired(self) -> None:
        lease = ExecutionLease(
            lease_id="l1",
            schedule_id="s1",
            worker_id="w1",
            acquired_at=datetime(2020, 1, 1, tzinfo=UTC),
            expires_at=datetime(2020, 1, 1, 0, 5, 0, tzinfo=UTC),
        )
        assert lease.is_expired is True

    def test_not_expired(self) -> None:
        lease = ExecutionLease(
            lease_id="l1",
            schedule_id="s1",
            worker_id="w1",
            acquired_at=utc_now(),
            expires_at=utc_now() + timedelta(hours=1),
        )
        assert lease.is_expired is False
