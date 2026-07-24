"""PgDetectionExecutionRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select, update

from detection.domain.aggregates.detection_execution import DetectionExecution
from detection.domain.exceptions.domain_exceptions import OptimisticLockConflict
from detection.domain.repositories.i_detection_execution_repository import (
    IDetectionExecutionRepository,
)
from detection.domain.value_objects.enums import ExecutionState, ExecutionTrigger
from detection.domain.value_objects.execution_finding import (
    DetectionRuleRef,
    ExecutionWindow,
)
from detection.domain.value_objects.identifiers import (
    DetectionExecutionId,
    DetectionFindingId,
    DetectionRuleId,
    TenantId,
)
from detection.domain.value_objects.keys import TelemetrySourceRef
from detection.infrastructure.persistence.models.execution_finding_model import (
    DetectionExecutionModel,
)
from detection.infrastructure.persistence.serialization import (
    execution_error_from_json,
    execution_error_to_json,
    execution_stats_from_json,
    execution_stats_to_json,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from detection.domain.value_objects.telemetry import TimeWindow


class PgDetectionExecutionRepository(IDetectionExecutionRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, execution: DetectionExecution) -> DetectionExecutionModel:
        return DetectionExecutionModel(
            id=execution.execution_id.value,
            tenant_id=execution.tenant_id.value,
            rule_id=execution.rule_ref.rule_id,
            rule_version=execution.rule_ref.rule_version,
            source_id=execution.source_ref.source_id,
            source_type=execution.source_ref.source_type,
            window_start=execution.window.start_time,
            window_end=execution.window.end_time,
            state=execution.state.value,
            trigger=execution.trigger.value,
            stats_json=execution_stats_to_json(execution.stats),
            error_json=execution_error_to_json(execution.error),
            finding_refs_json=[str(f) for f in execution.finding_refs],
            scheduled_at=execution.scheduled_at,
            started_at=execution.started_at,
            completed_at=execution.completed_at,
            created_at=execution.created_at,
            updated_at=execution.updated_at,
            row_version=execution.version,
        )

    def _to_domain(self, model: DetectionExecutionModel) -> DetectionExecution:
        refs = [
            DetectionFindingId(UUID(str(item)))
            for item in (model.finding_refs_json or [])
        ]
        return DetectionExecution(
            execution_id=DetectionExecutionId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            rule_ref=DetectionRuleRef(
                rule_id=model.rule_id, rule_version=model.rule_version
            ),
            source_ref=TelemetrySourceRef(
                source_id=model.source_id, source_type=model.source_type
            ),
            window=ExecutionWindow(
                start_time=model.window_start, end_time=model.window_end
            ),
            trigger=ExecutionTrigger(model.trigger),
            state=ExecutionState(model.state),
            stats=execution_stats_from_json(model.stats_json),
            error=execution_error_from_json(model.error_json),
            finding_refs=refs,
            scheduled_at=model.scheduled_at,
            started_at=model.started_at,
            completed_at=model.completed_at,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
        )

    async def save(self, execution: DetectionExecution) -> None:
        existing = await self._session.execute(
            select(DetectionExecutionModel).where(
                DetectionExecutionModel.id == execution.execution_id.value
            )
        )
        row = existing.scalar_one_or_none()
        if row is None:
            model = self._to_model(execution)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            execution._version = 1
            return
        if row.tenant_id != execution.tenant_id.value:
            raise OptimisticLockConflict(str(execution.execution_id))
        actual = row.row_version
        if execution.version == actual + 1 or execution.version == actual:
            expected = actual
        else:
            raise OptimisticLockConflict(str(execution.execution_id))
        result = await self._session.execute(
            update(DetectionExecutionModel)
            .where(
                DetectionExecutionModel.id == execution.execution_id.value,
                DetectionExecutionModel.tenant_id == execution.tenant_id.value,
                DetectionExecutionModel.row_version == expected,
            )
            .values(
                rule_id=execution.rule_ref.rule_id,
                rule_version=execution.rule_ref.rule_version,
                source_id=execution.source_ref.source_id,
                source_type=execution.source_ref.source_type,
                window_start=execution.window.start_time,
                window_end=execution.window.end_time,
                state=execution.state.value,
                trigger=execution.trigger.value,
                stats_json=execution_stats_to_json(execution.stats),
                error_json=execution_error_to_json(execution.error),
                finding_refs_json=[str(f) for f in execution.finding_refs],
                started_at=execution.started_at,
                completed_at=execution.completed_at,
                updated_at=execution.updated_at,
                row_version=expected + 1,
            )
            .returning(DetectionExecutionModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict(str(execution.execution_id))
        execution._version = int(new_version)
        await self._session.flush()

    async def find_by_id(
        self,
        execution_id: DetectionExecutionId,
        tenant_id: TenantId,
    ) -> DetectionExecution | None:
        stmt = select(DetectionExecutionModel).where(
            DetectionExecutionModel.id == execution_id.value,
            DetectionExecutionModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_by_rule(
        self,
        rule_id: DetectionRuleId,
        tenant_id: TenantId,
        window: TimeWindow | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionExecution]:
        stmt = select(DetectionExecutionModel).where(
            DetectionExecutionModel.tenant_id == tenant_id.value,
            DetectionExecutionModel.rule_id == str(rule_id),
        )
        if window is not None:
            stmt = stmt.where(
                DetectionExecutionModel.scheduled_at >= window.start,
                DetectionExecutionModel.scheduled_at < window.end,
            )
        stmt = (
            stmt.order_by(DetectionExecutionModel.scheduled_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_failed_by_tenant(
        self,
        tenant_id: TenantId,
        since: datetime,
    ) -> list[DetectionExecution]:
        stmt = select(DetectionExecutionModel).where(
            DetectionExecutionModel.tenant_id == tenant_id.value,
            DetectionExecutionModel.state == ExecutionState.FAILED.value,
            DetectionExecutionModel.completed_at >= since,
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_by_state(
        self,
        state: ExecutionState,
        tenant_id: TenantId,
    ) -> list[DetectionExecution]:
        stmt = select(DetectionExecutionModel).where(
            DetectionExecutionModel.tenant_id == tenant_id.value,
            DetectionExecutionModel.state == state.value,
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionExecution]:
        stmt = (
            select(DetectionExecutionModel)
            .where(DetectionExecutionModel.tenant_id == tenant_id.value)
            .order_by(DetectionExecutionModel.scheduled_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]
