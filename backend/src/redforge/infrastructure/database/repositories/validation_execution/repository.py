"""SqlAlchemy repository for the ValidationExecution aggregate.

Receives an active AsyncSession. NEVER commits or rolls back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select

from redforge.infrastructure.database.mappings.validation_execution_mapper import (
    execution_to_entity,
    execution_to_model,
    steps_to_models,
)
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.validation_execution.entity import ValidationExecution
    from redforge.domain.validation_execution.value_objects import ExecutionStatus
    from redforge.shared.identifiers import EntityId


class SqlAlchemyValidationExecutionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id_for_organization(
        self, execution_id: EntityId, organization_id: EntityId
    ) -> ValidationExecution | None:
        model = await self._get_model(str(execution_id), str(organization_id))
        if model is None:
            return None
        steps = await self._step_models(str(execution_id))
        return execution_to_entity(model, steps)

    async def get_by_id_for_organization_for_update(
        self, execution_id: EntityId, organization_id: EntityId
    ) -> ValidationExecution | None:
        model = await self._get_model(str(execution_id), str(organization_id), for_update=True)
        if model is None:
            return None
        steps = await self._step_models(str(execution_id))
        return execution_to_entity(model, steps)

    async def list_by_organization(
        self,
        organization_id: EntityId,
        status: ExecutionStatus | None,
        limit: int,
        offset: int,
    ) -> list[ValidationExecution]:
        stmt = select(ValidationExecutionModel).where(
            ValidationExecutionModel.organization_id == str(organization_id)
        )
        if status is not None:
            stmt = stmt.where(ValidationExecutionModel.status == str(status))
        stmt = (
            stmt.order_by(ValidationExecutionModel.created_at.desc()).limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        models = list(result.scalars().all())

        entities: list[ValidationExecution] = []
        for model in models:
            steps = await self._step_models(model.id)
            entities.append(execution_to_entity(model, steps))
        return entities

    async def count_by_status(self, organization_id: EntityId) -> dict[str, int]:
        stmt = (
            select(ValidationExecutionModel.status, func.count())
            .where(ValidationExecutionModel.organization_id == str(organization_id))
            .group_by(ValidationExecutionModel.status)
        )
        result = await self._session.execute(stmt)
        return {status: count for status, count in result.all()}

    async def count_by_status_since(
        self, organization_id: EntityId, since: datetime,
    ) -> dict[str, int]:
        """Bounded-period variant of count_by_status() — used only by
        the M15 Security Operations summary endpoint's server-controlled
        1h/24h/7d/30d windows."""
        stmt = (
            select(ValidationExecutionModel.status, func.count())
            .where(
                ValidationExecutionModel.organization_id == str(organization_id),
                ValidationExecutionModel.created_at >= since,
            )
            .group_by(ValidationExecutionModel.status)
        )
        result = await self._session.execute(stmt)
        return {status: count for status, count in result.all()}

    async def save(self, execution: ValidationExecution) -> None:
        existing = await self._get_model(str(execution.id), str(execution.organization_id))
        model = execution_to_model(execution)
        if existing is None:
            self._session.add(model)
        else:
            existing.status = model.status
            existing.policy_decision_id = model.policy_decision_id
            existing.policy_reason_code = model.policy_reason_code
            # cancellation_requested is monotonic (False -> True only,
            # never reset) and can be set concurrently by a DIFFERENT
            # in-memory aggregate instance (e.g. a concurrent POST
            # /cancel request racing the long-lived in-memory execution
            # object create_and_run() holds for its whole lifecycle).
            # OR-ing here, instead of overwriting, stops this save from
            # clobbering that flag back to False with a stale copy.
            existing.cancellation_requested = (
                existing.cancellation_requested or model.cancellation_requested
            )
            existing.failure_reason = model.failure_reason
            existing.updated_at = model.updated_at
            existing.started_at = model.started_at
            existing.completed_at = model.completed_at

        # Steps are replaced wholesale on every save — bounded to
        # max_steps (<= 6), so this is cheap and avoids incremental
        # per-step diffing logic.
        await self._session.execute(
            delete(ValidationExecutionStepModel).where(
                ValidationExecutionStepModel.execution_id == str(execution.id)
            )
        )
        for step_model in steps_to_models(execution):
            self._session.add(step_model)

        await self._session.flush()

    async def _get_model(
        self, execution_id: str, organization_id: str, *, for_update: bool = False,
    ) -> ValidationExecutionModel | None:
        stmt = select(ValidationExecutionModel).where(
            ValidationExecutionModel.id == execution_id,
            ValidationExecutionModel.organization_id == organization_id,
        )
        if for_update:
            stmt = stmt.with_for_update()
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def _step_models(self, execution_id: str) -> list[ValidationExecutionStepModel]:
        stmt = select(ValidationExecutionStepModel).where(
            ValidationExecutionStepModel.execution_id == execution_id
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
