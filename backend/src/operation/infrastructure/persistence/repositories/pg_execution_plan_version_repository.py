"""PgExecutionPlanVersionRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select, update

from operation.domain.aggregates.execution_plan_version import ExecutionPlanVersion
from operation.domain.exceptions.domain_exceptions import OptimisticLockConflict
from operation.domain.repositories.i_execution_plan_version_repository import (
    IExecutionPlanVersionRepository,
)
from operation.domain.value_objects.enums import ExecutionPlanVersionState
from operation.domain.value_objects.identifiers import (
    ExecutionPlanVersionId,
    OperationId,
    TenantId,
)
from operation.domain.value_objects.plan_vos import PlanHash, PlanSnapshot, SignedBy
from operation.infrastructure.persistence.models.operation_models import (
    ExecutionPlanVersionModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgExecutionPlanVersionRepository(IExecutionPlanVersionRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, pv: ExecutionPlanVersion) -> ExecutionPlanVersionModel:
        return ExecutionPlanVersionModel(
            id=pv.plan_version_id.value,
            tenant_id=pv.tenant_id.value,
            operation_id=pv.operation_id.value,
            version_number=pv.version_number,
            state=pv.state.value,
            snapshot=pv.snapshot.value,
            plan_hash=pv.plan_hash.value if pv.plan_hash else None,
            signed_by_operator_id=pv.signed_by.operator_id if pv.signed_by else None,
            signed_at=pv.signed_by.signed_at if pv.signed_by else None,
            signature=pv.signed_by.signature if pv.signed_by else None,
            created_at=pv.created_at,
            updated_at=pv.updated_at,
            row_version=pv.version,
        )

    def _to_domain(self, model: ExecutionPlanVersionModel) -> ExecutionPlanVersion:
        signed_by = None
        if (
            model.signed_by_operator_id is not None
            and model.signed_at is not None
            and model.signature is not None
        ):
            signed_by = SignedBy(
                operator_id=model.signed_by_operator_id,
                signed_at=model.signed_at,
                signature=model.signature,
            )
        return ExecutionPlanVersion(
            plan_version_id=ExecutionPlanVersionId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            operation_id=OperationId(model.operation_id),
            version_number=model.version_number,
            snapshot=PlanSnapshot(model.snapshot),
            plan_hash=PlanHash(model.plan_hash) if model.plan_hash else None,
            signed_by=signed_by,
            state=ExecutionPlanVersionState(model.state),
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
        )

    async def save(self, plan_version: ExecutionPlanVersion) -> None:
        existing = await self._session.execute(
            select(ExecutionPlanVersionModel).where(
                ExecutionPlanVersionModel.id == plan_version.plan_version_id.value
            )
        )
        row = existing.scalar_one_or_none()
        if row is None:
            model = self._to_model(plan_version)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            plan_version._version = 1
            return
        if row.tenant_id != plan_version.tenant_id.value:
            raise OptimisticLockConflict(
                str(plan_version.plan_version_id), 0, row.row_version
            )
        actual = row.row_version
        if plan_version.version == actual + 1 or plan_version.version == actual:
            expected = actual
        else:
            raise OptimisticLockConflict(
                str(plan_version.plan_version_id), plan_version.version, actual
            )
        result = await self._session.execute(
            update(ExecutionPlanVersionModel)
            .where(
                ExecutionPlanVersionModel.id == plan_version.plan_version_id.value,
                ExecutionPlanVersionModel.tenant_id == plan_version.tenant_id.value,
                ExecutionPlanVersionModel.row_version == expected,
            )
            .values(
                state=plan_version.state.value,
                snapshot=plan_version.snapshot.value,
                plan_hash=plan_version.plan_hash.value if plan_version.plan_hash else None,
                signed_by_operator_id=(
                    plan_version.signed_by.operator_id if plan_version.signed_by else None
                ),
                signed_at=plan_version.signed_by.signed_at if plan_version.signed_by else None,
                signature=plan_version.signed_by.signature if plan_version.signed_by else None,
                updated_at=plan_version.updated_at,
                row_version=expected + 1,
            )
            .returning(ExecutionPlanVersionModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict(
                str(plan_version.plan_version_id), expected, actual
            )
        plan_version._version = int(new_version)
        await self._session.flush()

    async def find_by_id(
        self,
        plan_version_id: ExecutionPlanVersionId,
        tenant_id: TenantId,
    ) -> ExecutionPlanVersion | None:
        result = await self._session.execute(
            select(ExecutionPlanVersionModel).where(
                ExecutionPlanVersionModel.id == plan_version_id.value,
                ExecutionPlanVersionModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_by_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> list[ExecutionPlanVersion]:
        result = await self._session.execute(
            select(ExecutionPlanVersionModel)
            .where(
                ExecutionPlanVersionModel.operation_id == operation_id.value,
                ExecutionPlanVersionModel.tenant_id == tenant_id.value,
            )
            .order_by(ExecutionPlanVersionModel.version_number.asc())
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_executing_for_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> ExecutionPlanVersion | None:
        result = await self._session.execute(
            select(ExecutionPlanVersionModel).where(
                ExecutionPlanVersionModel.operation_id == operation_id.value,
                ExecutionPlanVersionModel.tenant_id == tenant_id.value,
                ExecutionPlanVersionModel.state == ExecutionPlanVersionState.EXECUTING.value,
            )
        )
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def next_version_number(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> int:
        result = await self._session.execute(
            select(func.coalesce(func.max(ExecutionPlanVersionModel.version_number), 0)).where(
                ExecutionPlanVersionModel.operation_id == operation_id.value,
                ExecutionPlanVersionModel.tenant_id == tenant_id.value,
            )
        )
        current = int(result.scalar_one())
        return current + 1

    async def find_referencing_payload(
        self,
        tenant_id: TenantId,
        payload_id: str,
    ) -> list[ExecutionPlanVersion]:
        result = await self._session.execute(
            select(ExecutionPlanVersionModel).where(
                ExecutionPlanVersionModel.tenant_id == tenant_id.value,
                ExecutionPlanVersionModel.snapshot.contains(payload_id),
            )
        )
        return [self._to_domain(m) for m in result.scalars().all()]
