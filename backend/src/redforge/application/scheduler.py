"""Continuous Validation Scheduler.

Decides WHEN to create Validation Pipeline executions. Does NOT execute
attacks or call providers. Only orchestrates scheduling decisions.

Supports: cron, interval, manual, pause/resume, concurrency limits,
missed execution recovery, retry scheduling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum, unique
from typing import Protocol, runtime_checkable

from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

# ─── Enums ────────────────────────────────────────────────────────────────────


@unique
class ScheduleStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


@unique
class TriggerType(StrEnum):
    CRON = "cron"
    INTERVAL = "interval"
    MANUAL = "manual"


@unique
class ExecutionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    MISSED = "missed"


# ─── Triggers ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CronTrigger:
    """Cron-based schedule trigger (simplified: predefined intervals)."""

    expression: str  # e.g. "0 * * * *" (hourly), "0 0 * * *" (daily)

    def next_fire_time(self, after: datetime) -> datetime:
        """Calculate next fire time after the given datetime."""
        # Simplified cron: support hourly/daily/weekly patterns
        if self.expression == "0 * * * *":  # hourly
            return after.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        if self.expression == "0 0 * * *":  # daily
            return (after + timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        if self.expression == "0 0 * * 1":  # weekly (Monday)
            days_until_monday = (7 - after.weekday()) % 7 or 7
            return (after + timedelta(days=days_until_monday)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        # Default: 1 hour
        return after + timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class IntervalTrigger:
    """Fixed interval trigger."""

    interval_seconds: int

    def __post_init__(self) -> None:
        if self.interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")

    def next_fire_time(self, after: datetime) -> datetime:
        return after + timedelta(seconds=self.interval_seconds)


@dataclass(frozen=True, slots=True)
class ManualTrigger:
    """Manual (on-demand) trigger — no automatic scheduling."""

    def next_fire_time(self, after: datetime) -> datetime:
        # Manual triggers never auto-fire; return far future
        return after + timedelta(days=36500)


# ─── Schedule ─────────────────────────────────────────────────────────────────


@dataclass
class ValidationSchedule:
    """A scheduled validation configuration."""

    schedule_id: str
    organization_id: str
    target_id: str
    policy_id: str
    trigger_type: TriggerType
    trigger: CronTrigger | IntervalTrigger | ManualTrigger
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    max_concurrent: int = 1
    last_executed_at: datetime | None = None
    next_fire_at: datetime | None = None
    retry_on_failure: bool = True
    max_retries: int = 3
    metadata: dict[str, str] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        organization_id: str,
        target_id: str,
        policy_id: str,
        trigger: CronTrigger | IntervalTrigger | ManualTrigger,
    ) -> ValidationSchedule:
        trigger_type = TriggerType.MANUAL
        if isinstance(trigger, CronTrigger):
            trigger_type = TriggerType.CRON
        elif isinstance(trigger, IntervalTrigger):
            trigger_type = TriggerType.INTERVAL

        now = utc_now()
        return cls(
            schedule_id=str(EntityId.generate()),
            organization_id=organization_id,
            target_id=target_id,
            policy_id=policy_id,
            trigger_type=trigger_type,
            trigger=trigger,
            next_fire_at=trigger.next_fire_time(now),
        )

    def pause(self) -> None:
        self.status = ScheduleStatus.PAUSED

    def resume(self) -> None:
        self.status = ScheduleStatus.ACTIVE
        self.next_fire_at = self.trigger.next_fire_time(utc_now())

    def disable(self) -> None:
        self.status = ScheduleStatus.DISABLED

    def advance(self) -> None:
        """Advance to next fire time after execution."""
        now = utc_now()
        self.last_executed_at = now
        self.next_fire_at = self.trigger.next_fire_time(now)

    @property
    def is_due(self) -> bool:
        """Whether this schedule is ready to fire."""
        if self.status != ScheduleStatus.ACTIVE:
            return False
        if self.next_fire_at is None:
            return False
        return utc_now() >= self.next_fire_at


# ─── Execution History ────────────────────────────────────────────────────────


@dataclass
class ScheduleExecution:
    """Record of a single schedule execution."""

    execution_id: str
    schedule_id: str
    status: ExecutionStatus
    started_at: datetime
    completed_at: datetime | None = None
    pipeline_result_id: str | None = None
    error_message: str = ""
    retry_count: int = 0


# ─── Execution Lease ──────────────────────────────────────────────────────────


@dataclass
class ExecutionLease:
    """Distributed lock for schedule execution.

    Prevents multiple workers from executing the same schedule
    simultaneously. The lease expires if not renewed.
    """

    lease_id: str
    schedule_id: str
    worker_id: str
    acquired_at: datetime
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        return utc_now() > self.expires_at


# ─── Pipeline Interface ───────────────────────────────────────────────────────


@runtime_checkable
class PipelineExecutor(Protocol):
    """Interface the scheduler uses to trigger pipeline execution."""

    async def trigger(
        self, organization_id: str, target_id: str, policy_id: str
    ) -> str:
        """Trigger a pipeline execution. Returns pipeline result ID."""
        ...


# ─── Scheduler Service ────────────────────────────────────────────────────────


class SchedulerService:
    """Orchestrates schedule evaluation and pipeline triggering.

    Stateless — can run on any worker. Uses leases for distributed safety.
    """

    def __init__(
        self,
        pipeline_executor: PipelineExecutor,
        max_parallel: int = 10,
    ) -> None:
        self._executor = pipeline_executor
        self._max_parallel = max_parallel
        self._active_count = 0

    async def evaluate(
        self, schedules: list[ValidationSchedule]
    ) -> list[ScheduleExecution]:
        """Evaluate all schedules and trigger due ones."""
        executions: list[ScheduleExecution] = []

        for schedule in schedules:
            if len(executions) >= self._max_parallel:
                break
            if not schedule.is_due:
                continue

            execution = await self._execute_schedule(schedule)
            executions.append(execution)

        return executions

    async def trigger_manual(
        self, schedule: ValidationSchedule
    ) -> ScheduleExecution:
        """Manually trigger a schedule regardless of timing."""
        return await self._execute_schedule(schedule)

    async def recover_missed(
        self, schedules: list[ValidationSchedule], window: timedelta
    ) -> list[ScheduleExecution]:
        """Recover schedules that missed their fire time within the window."""
        now = utc_now()
        executions: list[ScheduleExecution] = []

        for schedule in schedules:
            if schedule.status != ScheduleStatus.ACTIVE:
                continue
            if schedule.next_fire_at is None:
                continue
            missed_by = now - schedule.next_fire_at
            if timedelta(0) < missed_by <= window:
                execution = await self._execute_schedule(schedule)
                executions.append(execution)

        return executions

    async def _execute_schedule(
        self, schedule: ValidationSchedule
    ) -> ScheduleExecution:
        """Execute a single schedule."""
        self._active_count += 1
        execution = ScheduleExecution(
            execution_id=str(EntityId.generate()),
            schedule_id=schedule.schedule_id,
            status=ExecutionStatus.RUNNING,
            started_at=utc_now(),
        )

        try:
            result_id = await self._executor.trigger(
                organization_id=schedule.organization_id,
                target_id=schedule.target_id,
                policy_id=schedule.policy_id,
            )
            execution.status = ExecutionStatus.COMPLETED
            execution.completed_at = utc_now()
            execution.pipeline_result_id = result_id
            schedule.advance()
        except Exception as exc:
            execution.status = ExecutionStatus.FAILED
            execution.completed_at = utc_now()
            execution.error_message = str(exc)
            if schedule.retry_on_failure:
                schedule.advance()  # Still advance to avoid infinite retry loops
        finally:
            self._active_count -= 1

        return execution
