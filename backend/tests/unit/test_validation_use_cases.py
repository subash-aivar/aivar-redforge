"""Unit tests for Validation use cases."""

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
    ValidationRunNotFoundError,
)
from redforge.domain.validations.use_cases import (
    CancelValidationUseCase,
    CompleteValidationCommand,
    CompleteValidationUseCase,
    FailValidationCommand,
    FailValidationUseCase,
    GetValidationRunUseCase,
    RetryValidationUseCase,
    ScheduleValidationCommand,
    ScheduleValidationUseCase,
    StartValidationUseCase,
)
from redforge.domain.validations.value_objects import TriggerType, ValidationStatus
from redforge.shared.identifiers import EntityId


class InMemoryValidationRunRepository:
    def __init__(self) -> None:
        self._store: dict[str, ValidationRun] = {}

    async def get_by_id(self, run_id: EntityId) -> ValidationRun | None:
        return self._store.get(str(run_id))

    async def list_by_target(
        self, target_id: EntityId, status: ValidationStatus | None = None
    ) -> list[ValidationRun]:
        runs = [r for r in self._store.values() if r.target_id == target_id]
        if status:
            runs = [r for r in runs if r.status == status]
        return runs

    async def list_by_organization(
        self, organization_id: EntityId, status: ValidationStatus | None = None
    ) -> list[ValidationRun]:
        runs = [r for r in self._store.values() if r.organization_id == organization_id]
        if status:
            runs = [r for r in runs if r.status == status]
        return runs

    async def save(self, run: ValidationRun) -> None:
        self._store[str(run.id)] = run


def _repo() -> InMemoryValidationRunRepository:
    return InMemoryValidationRunRepository()


async def _seed_scheduled(repo: InMemoryValidationRunRepository) -> ValidationRun:
    run = ValidationRun.schedule(
        organization_id=EntityId.generate(),
        target_id=EntityId.generate(),
        trigger_type=TriggerType.MANUAL,
    )
    run.collect_events()
    await repo.save(run)
    return run


async def _seed_running(repo: InMemoryValidationRunRepository) -> ValidationRun:
    run = await _seed_scheduled(repo)
    run.start()
    run.collect_events()
    await repo.save(run)
    return run


class TestScheduleValidation:
    async def test_schedules(self) -> None:
        repo = _repo()
        uc = ScheduleValidationUseCase(repo)
        result, events = await uc.execute(ScheduleValidationCommand(
            organization_id=str(EntityId.generate()),
            target_id=str(EntityId.generate()),
            trigger_type="manual",
        ))
        assert result.status == "scheduled"
        assert isinstance(events[0], ValidationScheduled)

    async def test_persists(self) -> None:
        repo = _repo()
        uc = ScheduleValidationUseCase(repo)
        result, _ = await uc.execute(ScheduleValidationCommand(
            organization_id=str(EntityId.generate()),
            target_id=str(EntityId.generate()),
            trigger_type="ci_cd",
            policy_id="pol-1",
        ))
        stored = await repo.get_by_id(EntityId.from_string(result.id))
        assert stored is not None
        assert stored.policy_id == "pol-1"


class TestStartValidation:
    async def test_starts(self) -> None:
        repo = _repo()
        run = await _seed_scheduled(repo)
        uc = StartValidationUseCase(repo)
        result, events = await uc.execute(str(run.id))
        assert result.status == "running"
        assert result.started_at is not None
        assert isinstance(events[0], ValidationStarted)

    async def test_not_found_raises(self) -> None:
        repo = _repo()
        uc = StartValidationUseCase(repo)
        with pytest.raises(ValidationRunNotFoundError):
            await uc.execute(str(EntityId.generate()))


class TestCompleteValidation:
    async def test_completes_with_summary(self) -> None:
        repo = _repo()
        run = await _seed_running(repo)
        uc = CompleteValidationUseCase(repo)
        result, events = await uc.execute(CompleteValidationCommand(
            run_id=str(run.id),
            total_checks=10,
            passed=8,
            failed=1,
            skipped=1,
            duration_ms=5000,
        ))
        assert result.status == "completed"
        assert result.summary is not None
        assert result.summary["total_checks"] == 10
        assert isinstance(events[0], ValidationCompleted)

    async def test_not_found_raises(self) -> None:
        repo = _repo()
        uc = CompleteValidationUseCase(repo)
        with pytest.raises(ValidationRunNotFoundError):
            await uc.execute(CompleteValidationCommand(
                run_id=str(EntityId.generate()),
                total_checks=1, passed=1, failed=0, skipped=0, duration_ms=10,
            ))


class TestFailValidation:
    async def test_fails(self) -> None:
        repo = _repo()
        run = await _seed_running(repo)
        uc = FailValidationUseCase(repo)
        result, events = await uc.execute(FailValidationCommand(
            run_id=str(run.id), reason="Timeout"
        ))
        assert result.status == "failed"
        assert result.failure_reason == "Timeout"
        assert isinstance(events[0], ValidationFailed)


class TestCancelValidation:
    async def test_cancels_scheduled(self) -> None:
        repo = _repo()
        run = await _seed_scheduled(repo)
        uc = CancelValidationUseCase(repo)
        result, events = await uc.execute(str(run.id))
        assert result.status == "cancelled"
        assert isinstance(events[0], ValidationCancelled)

    async def test_cancels_running(self) -> None:
        repo = _repo()
        run = await _seed_running(repo)
        uc = CancelValidationUseCase(repo)
        result, _ = await uc.execute(str(run.id))
        assert result.status == "cancelled"


class TestRetryValidation:
    async def test_retries_failed(self) -> None:
        repo = _repo()
        run = await _seed_running(repo)
        run.fail("Error")
        run.collect_events()
        await repo.save(run)
        uc = RetryValidationUseCase(repo)
        result, events = await uc.execute(str(run.id))
        assert result.status == "scheduled"
        assert result.id != str(run.id)
        assert isinstance(events[0], ValidationRetried)

    async def test_retry_non_failed_raises(self) -> None:
        repo = _repo()
        run = await _seed_running(repo)
        uc = RetryValidationUseCase(repo)
        with pytest.raises(InvalidValidationTransitionError):
            await uc.execute(str(run.id))


class TestGetValidationRun:
    async def test_gets(self) -> None:
        repo = _repo()
        run = await _seed_scheduled(repo)
        uc = GetValidationRunUseCase(repo)
        result = await uc.execute(str(run.id))
        assert result.id == str(run.id)

    async def test_not_found_raises(self) -> None:
        repo = _repo()
        uc = GetValidationRunUseCase(repo)
        with pytest.raises(ValidationRunNotFoundError):
            await uc.execute(str(EntityId.generate()))
