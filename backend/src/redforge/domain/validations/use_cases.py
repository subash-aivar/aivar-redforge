"""Application use cases for the Validation bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.validations.entity import ValidationRun
from redforge.domain.validations.exceptions import ValidationRunNotFoundError
from redforge.domain.validations.value_objects import TriggerType, ValidationSummary
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.validations.events import ValidationEvent
    from redforge.domain.validations.repository import ValidationRunRepository


# ─── Commands ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ScheduleValidationCommand:
    """Input for scheduling a new validation run."""

    organization_id: str
    target_id: str
    trigger_type: str
    policy_id: str | None = None


@dataclass(frozen=True, slots=True)
class CompleteValidationCommand:
    """Input for completing a validation run with summary."""

    run_id: str
    total_checks: int
    passed: int
    failed: int
    skipped: int
    duration_ms: int


@dataclass(frozen=True, slots=True)
class FailValidationCommand:
    """Input for marking a validation run as failed."""

    run_id: str
    reason: str


# ─── Results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ValidationRunResult:
    """Read-only representation of a ValidationRun."""

    id: str
    organization_id: str
    target_id: str
    policy_id: str | None
    trigger_type: str
    status: str
    started_at: str | None
    completed_at: str | None
    failure_reason: str | None
    summary: dict[str, int] | None
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, run: ValidationRun) -> ValidationRunResult:
        summary_dict = None
        if run.summary is not None:
            summary_dict = {
                "total_checks": run.summary.total_checks,
                "passed": run.summary.passed,
                "failed": run.summary.failed,
                "skipped": run.summary.skipped,
                "duration_ms": run.summary.duration_ms,
            }
        return cls(
            id=str(run.id),
            organization_id=str(run.organization_id),
            target_id=str(run.target_id),
            policy_id=run.policy_id,
            trigger_type=str(run.trigger_type),
            status=str(run.status),
            started_at=run.started_at.isoformat() if run.started_at else None,
            completed_at=run.completed_at.isoformat() if run.completed_at else None,
            failure_reason=run.failure_reason,
            summary=summary_dict,
            created_at=run.timestamps.created_at.isoformat(),
            updated_at=run.timestamps.updated_at.isoformat(),
        )


# ─── Use Cases ────────────────────────────────────────────────────────────────


class ScheduleValidationUseCase:
    """Schedule a new validation run against an AI Target."""

    def __init__(self, repository: ValidationRunRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: ScheduleValidationCommand
    ) -> tuple[ValidationRunResult, list[ValidationEvent]]:
        run = ValidationRun.schedule(
            organization_id=EntityId.from_string(command.organization_id),
            target_id=EntityId.from_string(command.target_id),
            trigger_type=TriggerType(command.trigger_type),
            policy_id=command.policy_id,
        )
        await self._repository.save(run)
        events = run.collect_events()
        return ValidationRunResult.from_entity(run), events


class StartValidationUseCase:
    """Start execution of a scheduled validation run."""

    def __init__(self, repository: ValidationRunRepository) -> None:
        self._repository = repository

    async def execute(
        self, run_id: str
    ) -> tuple[ValidationRunResult, list[ValidationEvent]]:
        run = await self._load(run_id)
        run.start()
        await self._repository.save(run)
        events = run.collect_events()
        return ValidationRunResult.from_entity(run), events

    async def _load(self, run_id: str) -> ValidationRun:
        entity_id = EntityId.from_string(run_id)
        run = await self._repository.get_by_id(entity_id)
        if run is None:
            raise ValidationRunNotFoundError(run_id)
        return run


class CompleteValidationUseCase:
    """Mark a validation run as completed with summary metrics."""

    def __init__(self, repository: ValidationRunRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: CompleteValidationCommand
    ) -> tuple[ValidationRunResult, list[ValidationEvent]]:
        entity_id = EntityId.from_string(command.run_id)
        run = await self._repository.get_by_id(entity_id)
        if run is None:
            raise ValidationRunNotFoundError(command.run_id)

        summary = ValidationSummary(
            total_checks=command.total_checks,
            passed=command.passed,
            failed=command.failed,
            skipped=command.skipped,
            duration_ms=command.duration_ms,
        )
        run.attach_summary(summary)
        run.complete()

        await self._repository.save(run)
        events = run.collect_events()
        return ValidationRunResult.from_entity(run), events


class FailValidationUseCase:
    """Mark a validation run as failed."""

    def __init__(self, repository: ValidationRunRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: FailValidationCommand
    ) -> tuple[ValidationRunResult, list[ValidationEvent]]:
        entity_id = EntityId.from_string(command.run_id)
        run = await self._repository.get_by_id(entity_id)
        if run is None:
            raise ValidationRunNotFoundError(command.run_id)

        run.fail(command.reason)

        await self._repository.save(run)
        events = run.collect_events()
        return ValidationRunResult.from_entity(run), events


class CancelValidationUseCase:
    """Cancel a scheduled or running validation."""

    def __init__(self, repository: ValidationRunRepository) -> None:
        self._repository = repository

    async def execute(
        self, run_id: str
    ) -> tuple[ValidationRunResult, list[ValidationEvent]]:
        entity_id = EntityId.from_string(run_id)
        run = await self._repository.get_by_id(entity_id)
        if run is None:
            raise ValidationRunNotFoundError(run_id)

        run.cancel()

        await self._repository.save(run)
        events = run.collect_events()
        return ValidationRunResult.from_entity(run), events


class RetryValidationUseCase:
    """Retry a failed validation run (creates a new run)."""

    def __init__(self, repository: ValidationRunRepository) -> None:
        self._repository = repository

    async def execute(
        self, run_id: str
    ) -> tuple[ValidationRunResult, list[ValidationEvent]]:
        entity_id = EntityId.from_string(run_id)
        original = await self._repository.get_by_id(entity_id)
        if original is None:
            raise ValidationRunNotFoundError(run_id)

        new_run = original.retry()

        await self._repository.save(new_run)
        events = new_run.collect_events()
        return ValidationRunResult.from_entity(new_run), events


class GetValidationRunUseCase:
    """Retrieve a validation run by id."""

    def __init__(self, repository: ValidationRunRepository) -> None:
        self._repository = repository

    async def execute(self, run_id: str) -> ValidationRunResult:
        entity_id = EntityId.from_string(run_id)
        run = await self._repository.get_by_id(entity_id)
        if run is None:
            raise ValidationRunNotFoundError(run_id)
        return ValidationRunResult.from_entity(run)
