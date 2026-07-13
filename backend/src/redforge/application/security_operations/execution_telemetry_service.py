"""ExecutionTelemetryService — M15.

A read-only projection over the existing M11 ValidationExecution
aggregate and its own comprehensive validation_execution_events log.
Owns nothing — every mutation still goes exclusively through
ValidationExecutionService (create_and_run/cancel). This service only
derives a backend-controlled phase/timeline/result-summary on top of
data that already exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from redforge.application.security_operations.execution_phase import phase_for_event_type
from redforge.domain.security_operations.value_objects import (
    EXECUTIONS_MAX_PAGE_SIZE,
    ExecutionPhase,
)

if TYPE_CHECKING:
    from redforge.application.validation_execution.execution_service import (
        EventDTO,
        ValidationExecutionDTO,
        ValidationExecutionService,
    )

_TERMINAL_STATUSES = frozenset({
    "completed", "partially_completed", "failed", "cancelled", "denied",
})


@dataclass(frozen=True, slots=True)
class TelemetryTimelineEntryDTO:
    phase: str
    event_type: str
    title: str
    occurred_at: str


@dataclass(frozen=True, slots=True)
class ExecutionTelemetrySummaryDTO:
    id: str
    organization_id: str
    target_id: str
    trigger: str
    continuous_policy_id: str | None
    profile: str
    state: str
    phase: str
    latest_event_title: str | None
    created_at: str
    started_at: str | None
    completed_at: str | None


@dataclass(frozen=True, slots=True)
class ExecutionTelemetryDetailDTO:
    summary: ExecutionTelemetrySummaryDTO
    timeline: list[TelemetryTimelineEntryDTO] = field(default_factory=list)
    result_summary: str = ""


def _phase_for_status(status: str) -> str:
    if status in ("pending", "policy_checking"):
        return str(ExecutionPhase.AUTHORIZATION)
    if status == "denied":
        return str(ExecutionPhase.AUTHORIZATION)
    if status in _TERMINAL_STATUSES:
        return str(ExecutionPhase.COMPLETED)
    return str(ExecutionPhase.UNKNOWN)


_MAX_RESULT_SUMMARY_LENGTH = 500


def _result_summary(dto: ValidationExecutionDTO, events: list[EventDTO]) -> str:
    if dto.status not in _TERMINAL_STATUSES:
        return ""
    validated = sum(1 for s in dto.steps if s.protocol_validation_state == "validated")
    conditions_appeared = sum(1 for e in events if e.event_type == "condition_ingested")
    parts: list[str] = []
    if validated:
        parts.append(f"{validated} service{'s' if validated != 1 else ''} validated.")
    if conditions_appeared:
        parts.append(
            f"{conditions_appeared} condition{'s' if conditions_appeared != 1 else ''} observed."
        )
    if dto.status == "failed":
        parts.append(f"Failed: {dto.failure_reason or 'unknown reason'}.")
    if dto.status == "denied":
        parts.append(f"Blocked: authorization denied ({dto.policy_reason_code or 'unknown'}).")
    if dto.status == "cancelled":
        parts.append("Cancelled.")
    summary = " ".join(parts) if parts else "Completed with no findings."
    # Defensive bound matching OperationalEvent's own title/summary cap —
    # dto.failure_reason is already a controlled message today, but this
    # keeps the module's own "bounded scalar" contract true by
    # construction rather than by trusting every upstream caller forever.
    return summary[:_MAX_RESULT_SUMMARY_LENGTH]


class ExecutionTelemetryService:
    def __init__(self, execution_service: ValidationExecutionService) -> None:
        self._execution_service = execution_service

    async def list_executions(
        self,
        organization_id: str,
        state: str | None = None,
        trigger: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ExecutionTelemetrySummaryDTO]:
        from redforge.core.exceptions import ValidationError
        from redforge.domain.validation_execution.value_objects import ExecutionStatus

        if state is not None:
            try:
                ExecutionStatus(state)
            except ValueError as exc:
                raise ValidationError(f"Unknown execution state: {state!r}") from exc

        limit = min(limit, EXECUTIONS_MAX_PAGE_SIZE)
        executions = await self._execution_service.list_by_organization(
            organization_id, state, limit, offset,
        )
        if trigger is not None:
            executions = [e for e in executions if e.trigger == trigger]
        if target_id is not None:
            executions = [e for e in executions if e.target_id == target_id]

        summaries: list[ExecutionTelemetrySummaryDTO] = []
        for dto in executions:
            latest_title: str | None = None
            if dto.status not in _TERMINAL_STATUSES:
                events = await self._execution_service.list_events(
                    organization_id, dto.id, after_sequence=0, limit=1000,
                )
                if events:
                    latest_title = events[-1].event_type
            summaries.append(
                ExecutionTelemetrySummaryDTO(
                    id=dto.id, organization_id=dto.organization_id, target_id=dto.target_id,
                    trigger=dto.trigger, continuous_policy_id=dto.continuous_policy_id,
                    profile=dto.profile, state=dto.status, phase=_phase_for_status(dto.status),
                    latest_event_title=latest_title, created_at=dto.created_at,
                    started_at=dto.started_at, completed_at=dto.completed_at,
                )
            )
        return summaries

    async def get_detail(
        self, organization_id: str, execution_id: str,
    ) -> ExecutionTelemetryDetailDTO:
        """Raises ValidationExecutionNotFoundError (mapped to 404) for
        an unknown, cross-tenant, OR syntactically malformed
        execution_id — never a 500. ValidationExecutionService.
        get_by_id() itself calls EntityId.from_string() unguarded (a
        pre-existing gap in M11, flagged during M14 for separate
        follow-up rather than touched here); this call site closes it
        locally, matching M14's own `_safe_entity_id()` precedent."""
        from redforge.domain.validation_execution.exceptions import (
            ValidationExecutionNotFoundError,
        )

        try:
            dto = await self._execution_service.get_by_id(organization_id, execution_id)
        except ValueError as exc:
            raise ValidationExecutionNotFoundError(execution_id) from exc
        events = await self._execution_service.list_events(
            organization_id, execution_id, after_sequence=0, limit=1000,
        )
        timeline = [
            TelemetryTimelineEntryDTO(
                phase=str(phase_for_event_type(e.event_type, e.payload.get("step_type"))),
                event_type=e.event_type, title=e.event_type.replace("_", " "),
                occurred_at=e.occurred_at,
            )
            for e in events
        ]
        latest_title = events[-1].event_type if events else None
        phase = timeline[-1].phase if timeline else _phase_for_status(dto.status)
        summary = ExecutionTelemetrySummaryDTO(
            id=dto.id, organization_id=dto.organization_id, target_id=dto.target_id,
            trigger=dto.trigger, continuous_policy_id=dto.continuous_policy_id,
            profile=dto.profile, state=dto.status, phase=phase,
            latest_event_title=latest_title, created_at=dto.created_at,
            started_at=dto.started_at, completed_at=dto.completed_at,
        )
        return ExecutionTelemetryDetailDTO(
            summary=summary, timeline=timeline, result_summary=_result_summary(dto, events),
        )
