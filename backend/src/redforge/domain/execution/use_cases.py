"""Application use cases for the Execution Engine bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.execution.entity import ExecutionPlan
from redforge.domain.execution.exceptions import PlanNotFoundError
from redforge.domain.execution.value_objects import (
    ExecutionMode,
    ExecutionStage,
    ExecutionStep,
    FailureStrategy,
    StepResult,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.execution.events import ExecutionEvent
    from redforge.domain.execution.repository import ExecutionPlanRepository


@dataclass(frozen=True, slots=True)
class CreatePlanCommand:
    """Input for generating an execution plan."""

    run_id: str
    policy_id: str
    target_id: str
    attack_ids: list[str]
    failure_strategy: str = "continue"


@dataclass(frozen=True, slots=True)
class PlanResult:
    """Read-only representation of an ExecutionPlan."""

    id: str
    run_id: str
    policy_id: str
    target_id: str
    status: str
    stage_count: int
    total_steps: int
    completed_steps: int
    failed_steps: int
    failure_reason: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, plan: ExecutionPlan) -> PlanResult:
        return cls(
            id=str(plan.id),
            run_id=str(plan.run_id),
            policy_id=str(plan.policy_id),
            target_id=str(plan.target_id),
            status=str(plan.status),
            stage_count=len(plan.stages),
            total_steps=plan.total_steps,
            completed_steps=plan.completed_steps,
            failed_steps=plan.failed_steps,
            failure_reason=plan.failure_reason,
            created_at=plan.timestamps.created_at.isoformat(),
            updated_at=plan.timestamps.updated_at.isoformat(),
        )


class CreatePlanUseCase:
    """Generate an execution plan from resolved attacks."""

    def __init__(self, repository: ExecutionPlanRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: CreatePlanCommand
    ) -> tuple[PlanResult, list[ExecutionEvent]]:
        target_id = command.target_id
        steps = [
            ExecutionStep(
                step_id=f"step-{i}",
                attack_id=aid,
                target_id=target_id,
                order=i,
            )
            for i, aid in enumerate(command.attack_ids)
        ]
        stage = ExecutionStage(
            stage_id="stage-0",
            name="default",
            mode=ExecutionMode.SEQUENTIAL,
            steps=tuple(steps),
        )

        plan = ExecutionPlan.create(
            run_id=EntityId.from_string(command.run_id),
            policy_id=EntityId.from_string(command.policy_id),
            target_id=EntityId.from_string(command.target_id),
            stages=[stage],
            failure_strategy=FailureStrategy(command.failure_strategy),
        )
        await self._repository.save(plan)
        events = plan.collect_events()
        return PlanResult.from_entity(plan), events


class StartPlanUseCase:
    """Start execution of a pending plan."""

    def __init__(self, repository: ExecutionPlanRepository) -> None:
        self._repository = repository

    async def execute(
        self, plan_id: str
    ) -> tuple[PlanResult, list[ExecutionEvent]]:
        entity_id = EntityId.from_string(plan_id)
        plan = await self._repository.get_by_id(entity_id)
        if plan is None:
            raise PlanNotFoundError(plan_id)
        plan.start()
        await self._repository.save(plan)
        events = plan.collect_events()
        return PlanResult.from_entity(plan), events


class RecordStepResultUseCase:
    """Record the result of a completed step."""

    def __init__(self, repository: ExecutionPlanRepository) -> None:
        self._repository = repository

    async def execute(
        self, plan_id: str, step_id: str, result: StepResult
    ) -> tuple[PlanResult, list[ExecutionEvent]]:
        entity_id = EntityId.from_string(plan_id)
        plan = await self._repository.get_by_id(entity_id)
        if plan is None:
            raise PlanNotFoundError(plan_id)
        plan.record_step_result(step_id, result)
        await self._repository.save(plan)
        events = plan.collect_events()
        return PlanResult.from_entity(plan), events


class CancelPlanUseCase:
    """Cancel a running or pending plan."""

    def __init__(self, repository: ExecutionPlanRepository) -> None:
        self._repository = repository

    async def execute(
        self, plan_id: str
    ) -> tuple[PlanResult, list[ExecutionEvent]]:
        entity_id = EntityId.from_string(plan_id)
        plan = await self._repository.get_by_id(entity_id)
        if plan is None:
            raise PlanNotFoundError(plan_id)
        plan.cancel()
        await self._repository.save(plan)
        events = plan.collect_events()
        return PlanResult.from_entity(plan), events


class GetPlanUseCase:
    """Retrieve an execution plan by id."""

    def __init__(self, repository: ExecutionPlanRepository) -> None:
        self._repository = repository

    async def execute(self, plan_id: str) -> PlanResult:
        entity_id = EntityId.from_string(plan_id)
        plan = await self._repository.get_by_id(entity_id)
        if plan is None:
            raise PlanNotFoundError(plan_id)
        return PlanResult.from_entity(plan)
