"""DetectionExecution aggregate root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

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
    TenantMismatch,
)
from detection.domain.value_objects.enums import ExecutionState
from detection.domain.value_objects.execution_finding import ExecutionStats
from detection.domain.value_objects.identifiers import DetectionExecutionId

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.value_objects.enums import ExecutionTrigger
    from detection.domain.value_objects.execution_finding import (
        DetectionRuleRef,
        ExecutionError,
        ExecutionWindow,
    )
    from detection.domain.value_objects.identifiers import (
        DetectionFindingId,
        TenantId,
    )
    from detection.domain.value_objects.keys import TelemetrySourceRef

_ALLOWED: dict[ExecutionState, frozenset[ExecutionState]] = {
    ExecutionState.SCHEDULED: frozenset(
        {
            ExecutionState.RUNNING,
            ExecutionState.SKIPPED,
            ExecutionState.FAILED,
            ExecutionState.TIMEDOUT,
        }
    ),
    ExecutionState.RUNNING: frozenset(
        {
            ExecutionState.COMPLETED,
            ExecutionState.FAILED,
            ExecutionState.TIMEDOUT,
        }
    ),
    ExecutionState.COMPLETED: frozenset(),
    ExecutionState.FAILED: frozenset(),
    ExecutionState.TIMEDOUT: frozenset(),
    ExecutionState.SKIPPED: frozenset(),
}


class DetectionExecution:
    """Record of a single rule evaluation against a telemetry window."""

    __slots__ = (
        "_pending_events",
        "_version",
        "completed_at",
        "created_at",
        "error",
        "execution_id",
        "finding_refs",
        "rule_ref",
        "scheduled_at",
        "source_ref",
        "started_at",
        "state",
        "stats",
        "tenant_id",
        "trigger",
        "updated_at",
        "window",
    )

    def __init__(
        self,
        execution_id: DetectionExecutionId,
        tenant_id: TenantId,
        rule_ref: DetectionRuleRef,
        source_ref: TelemetrySourceRef,
        window: ExecutionWindow,
        trigger: ExecutionTrigger,
        state: ExecutionState,
        stats: ExecutionStats,
        error: ExecutionError | None,
        finding_refs: list[DetectionFindingId],
        scheduled_at: datetime,
        started_at: datetime | None,
        completed_at: datetime | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.execution_id = execution_id
        self.tenant_id = tenant_id
        self.rule_ref = rule_ref
        self.source_ref = source_ref
        self.window = window
        self.trigger = trigger
        self.state = state
        self.stats = stats
        self.error = error
        self.finding_refs = list(finding_refs)
        self.scheduled_at = scheduled_at
        self.started_at = started_at
        self.completed_at = completed_at
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: ExecutionState) -> None:
        allowed = _ALLOWED.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(self.state.value, to_state.value)
        self.state = to_state

    @classmethod
    def schedule(
        cls,
        *,
        tenant_id: TenantId,
        rule_ref: DetectionRuleRef,
        source_ref: TelemetrySourceRef,
        window: ExecutionWindow,
        trigger: ExecutionTrigger,
        now: datetime,
        execution_id: DetectionExecutionId | None = None,
    ) -> DetectionExecution:
        eid = execution_id or DetectionExecutionId.generate()
        aggregate = cls(
            execution_id=eid,
            tenant_id=tenant_id,
            rule_ref=rule_ref,
            source_ref=source_ref,
            window=window,
            trigger=trigger,
            state=ExecutionState.SCHEDULED,
            stats=ExecutionStats(),
            error=None,
            finding_refs=[],
            scheduled_at=now,
            started_at=None,
            completed_at=None,
            created_at=now,
            updated_at=now,
            version=0,
        )
        aggregate._emit(
            DetectionExecutionScheduled(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(eid),
                aggregate_type="DetectionExecution",
                rule_id=rule_ref.rule_id,
                rule_version=rule_ref.rule_version,
                source_id=source_ref.source_id,
                trigger=trigger.value,
            )
        )
        return aggregate

    def start(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(ExecutionState.RUNNING)
        self.started_at = now
        self._mutate(now)
        self._emit(
            DetectionExecutionStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.execution_id),
                aggregate_type="DetectionExecution",
                rule_id=self.rule_ref.rule_id,
            )
        )

    def complete(
        self,
        *,
        tenant_id: TenantId,
        stats: ExecutionStats,
        finding_refs: list[DetectionFindingId] | None = None,
        now: datetime,
    ) -> None:
        """Complete from Running (call start first if still Scheduled)."""
        self._assert_tenant(tenant_id)
        if self.state == ExecutionState.SCHEDULED:
            self.start(tenant_id=tenant_id, now=now)
        self._transition(ExecutionState.COMPLETED)
        self.stats = stats
        if finding_refs is not None:
            seen = {str(f) for f in self.finding_refs}
            for fid in finding_refs:
                if str(fid) not in seen:
                    self.finding_refs.append(fid)
                    seen.add(str(fid))
        self.completed_at = now
        self._mutate(now)
        self._emit(
            DetectionExecutionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.execution_id),
                aggregate_type="DetectionExecution",
                rule_id=self.rule_ref.rule_id,
                finding_count=stats.findings_produced,
                duration_ms=stats.duration_ms,
            )
        )

    def record_result(
        self,
        *,
        tenant_id: TenantId,
        stats: ExecutionStats,
        finding_refs: list[DetectionFindingId] | None = None,
        now: datetime,
    ) -> None:
        """Idempotent-friendly completion from Scheduled or Running."""
        self._assert_tenant(tenant_id)
        if self.state == ExecutionState.SCHEDULED:
            self._transition(ExecutionState.RUNNING)
            self.started_at = now
            self._emit(
                DetectionExecutionStarted(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.execution_id),
                    aggregate_type="DetectionExecution",
                    rule_id=self.rule_ref.rule_id,
                )
            )
        if self.state != ExecutionState.RUNNING:
            raise ExecutionLifecycleBlocked(
                f"cannot record result from state {self.state.value}"
            )
        self._transition(ExecutionState.COMPLETED)
        self.stats = stats
        if finding_refs is not None:
            seen = {str(f) for f in self.finding_refs}
            for fid in finding_refs:
                if str(fid) not in seen:
                    self.finding_refs.append(fid)
                    seen.add(str(fid))
        self.completed_at = now
        self._mutate(now)
        self._emit(
            DetectionExecutionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.execution_id),
                aggregate_type="DetectionExecution",
                rule_id=self.rule_ref.rule_id,
                finding_count=stats.findings_produced,
                duration_ms=stats.duration_ms,
            )
        )

    def fail(
        self,
        *,
        tenant_id: TenantId,
        error: ExecutionError,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state == ExecutionState.SCHEDULED:
            self._transition(ExecutionState.RUNNING)
            self.started_at = now
        self._transition(ExecutionState.FAILED)
        self.error = error
        self.completed_at = now
        self._mutate(now)
        self._emit(
            DetectionExecutionFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.execution_id),
                aggregate_type="DetectionExecution",
                rule_id=self.rule_ref.rule_id,
                error_type=error.error_type,
                error_message=error.error_message,
            )
        )

    def timeout(
        self,
        *,
        tenant_id: TenantId,
        duration_ms: float,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if duration_ms < 0:
            raise InvalidArgument("duration_ms", "must be >= 0")
        if self.state == ExecutionState.SCHEDULED:
            self._transition(ExecutionState.RUNNING)
            self.started_at = now
        self._transition(ExecutionState.TIMEDOUT)
        self.stats = ExecutionStats(
            telemetry_records_evaluated=self.stats.telemetry_records_evaluated,
            findings_produced=self.stats.findings_produced,
            duration_ms=duration_ms,
            cpu_ms=self.stats.cpu_ms,
        )
        self.completed_at = now
        self._mutate(now)
        self._emit(
            DetectionExecutionTimedOut(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.execution_id),
                aggregate_type="DetectionExecution",
                rule_id=self.rule_ref.rule_id,
                duration_ms=duration_ms,
            )
        )

    def skip(self, *, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "required")
        self._transition(ExecutionState.SKIPPED)
        self.error = None
        self.completed_at = now
        self._mutate(now)

    def add_finding_ref(
        self,
        *,
        tenant_id: TenantId,
        finding_id: DetectionFindingId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state in {
            ExecutionState.FAILED,
            ExecutionState.TIMEDOUT,
            ExecutionState.SKIPPED,
        }:
            raise ExecutionLifecycleBlocked(
                "cannot attach findings to terminal non-success execution"
            )
        if any(str(f) == str(finding_id) for f in self.finding_refs):
            return
        self.finding_refs.append(finding_id)
        self._mutate(now)
