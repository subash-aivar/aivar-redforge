"""Orchestration run aggregate for M26 Phase 8 platform integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.platform.events import (
    PlatformDomainEvent,
    PlatformOrchestrationCompleted,
    PlatformOrchestrationStarted,
    PlatformOrchestrationStepFailed,
)
from redforge.domain.cloud_security.platform.exceptions import InvalidPlatformArgumentError
from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationRunId,
    OrchestrationScope,
    RunStatus,
    StepName,
    StepStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass
class OrchestrationStepResult:
    step_name: StepName
    status: StepStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: float | None = None
    message: str = ""
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_name": self.step_name.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "message": self.message,
            "error": self.error,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrchestrationStepResult:
        started = data.get("started_at")
        completed = data.get("completed_at")
        return cls(
            step_name=StepName(str(data["step_name"])),
            status=StepStatus(str(data["status"])),
            started_at=datetime.fromisoformat(started) if isinstance(started, str) else None,
            completed_at=(
                datetime.fromisoformat(completed) if isinstance(completed, str) else None
            ),
            duration_ms=float(data["duration_ms"]) if data.get("duration_ms") is not None else None,
            message=str(data.get("message") or ""),
            error=str(data["error"]) if data.get("error") else None,
            details=dict(data.get("details") or {}),
        )


@dataclass
class OrchestrationRun:
    id: OrchestrationRunId
    organization_id: OrganizationId
    scope: OrchestrationScope
    target_id: str
    status: RunStatus
    steps: list[OrchestrationStepResult]
    diagnostics: dict[str, Any]
    operation_id: str
    correlation_id: str
    request_id: str
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    row_version: int = 1
    _pending_events: list[PlatformDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def start(
        cls,
        *,
        organization_id: OrganizationId,
        scope: OrchestrationScope,
        target_id: str,
        operation_id: str,
        correlation_id: str = "",
        request_id: str = "",
        now: datetime | None = None,
        run_id: OrchestrationRunId | None = None,
    ) -> OrchestrationRun:
        if not target_id.strip():
            raise InvalidPlatformArgumentError("target_id", "required")
        if not operation_id.strip():
            raise InvalidPlatformArgumentError("operation_id", "required")
        ts = now or datetime.now(UTC)
        rid = run_id or OrchestrationRunId.generate()
        run = cls(
            id=rid,
            organization_id=organization_id,
            scope=scope,
            target_id=target_id.strip(),
            status=RunStatus.RUNNING,
            steps=[],
            diagnostics={},
            operation_id=operation_id.strip(),
            correlation_id=correlation_id.strip(),
            request_id=request_id.strip(),
            started_at=ts,
            completed_at=None,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        run._pending_events.append(
            PlatformOrchestrationStarted(
                organization_id=str(organization_id),
                run_id=str(rid),
                occurred_at=ts,
                scope=scope.value,
                target_id=run.target_id,
                operation_id=run.operation_id,
            )
        )
        return run

    def record_step(self, result: OrchestrationStepResult) -> None:
        self.steps.append(result)
        self.updated_at = datetime.now(UTC)
        self.row_version += 1
        if result.status == StepStatus.FAILED:
            self._pending_events.append(
                PlatformOrchestrationStepFailed(
                    organization_id=str(self.organization_id),
                    run_id=str(self.id),
                    occurred_at=result.completed_at or datetime.now(UTC),
                    step_name=result.step_name.value,
                    error=result.error or result.message or "step failed",
                )
            )

    def fail_step(
        self,
        step_name: StepName,
        error: str,
        *,
        started_at: datetime | None = None,
        duration_ms: float | None = None,
        details: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> OrchestrationStepResult:
        ts = now or datetime.now(UTC)
        result = OrchestrationStepResult(
            step_name=step_name,
            status=StepStatus.FAILED,
            started_at=started_at,
            completed_at=ts,
            duration_ms=duration_ms,
            message="step failed",
            error=error.strip()[:4000] if error else "unknown error",
            details=dict(details or {}),
        )
        self.record_step(result)
        return result

    def complete(
        self,
        *,
        diagnostics: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        if diagnostics:
            self.diagnostics = {**self.diagnostics, **diagnostics}
        failed = sum(1 for s in self.steps if s.status == StepStatus.FAILED)
        completed = sum(1 for s in self.steps if s.status == StepStatus.COMPLETED)
        if failed == 0:
            self.status = RunStatus.COMPLETED
        elif completed == 0 and failed > 0:
            self.status = RunStatus.FAILED
        else:
            self.status = RunStatus.PARTIAL
        self.completed_at = ts
        self.updated_at = ts
        self.row_version += 1
        self._pending_events.append(
            PlatformOrchestrationCompleted(
                organization_id=str(self.organization_id),
                run_id=str(self.id),
                occurred_at=ts,
                status=self.status.value,
                steps_completed=completed,
                steps_failed=failed,
            )
        )

    def mark_partial(
        self,
        *,
        diagnostics: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        if diagnostics:
            self.diagnostics = {**self.diagnostics, **diagnostics}
        self.status = RunStatus.PARTIAL
        self.completed_at = ts
        self.updated_at = ts
        self.row_version += 1
        failed = sum(1 for s in self.steps if s.status == StepStatus.FAILED)
        completed = sum(1 for s in self.steps if s.status == StepStatus.COMPLETED)
        self._pending_events.append(
            PlatformOrchestrationCompleted(
                organization_id=str(self.organization_id),
                run_id=str(self.id),
                occurred_at=ts,
                status=self.status.value,
                steps_completed=completed,
                steps_failed=failed,
            )
        )

    def fail(
        self,
        error: str,
        *,
        diagnostics: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        if diagnostics:
            self.diagnostics = {**self.diagnostics, **diagnostics}
        self.diagnostics["fatal_error"] = error.strip()[:4000]
        self.status = RunStatus.FAILED
        self.completed_at = ts
        self.updated_at = ts
        self.row_version += 1
        failed = sum(1 for s in self.steps if s.status == StepStatus.FAILED)
        completed = sum(1 for s in self.steps if s.status == StepStatus.COMPLETED)
        self._pending_events.append(
            PlatformOrchestrationCompleted(
                organization_id=str(self.organization_id),
                run_id=str(self.id),
                occurred_at=ts,
                status=self.status.value,
                steps_completed=completed,
                steps_failed=max(failed, 1),
            )
        )

    def pop_events(self) -> list[PlatformDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
