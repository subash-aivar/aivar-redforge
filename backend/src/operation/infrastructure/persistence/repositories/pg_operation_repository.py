"""PgOperationRepository — Operation aggregate with child tables."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import delete, select, update

from operation.domain.aggregates.operation import Operation
from operation.domain.entities.operation_entities import (
    ExecutionStep,
    OperationApproval,
    OperationObjective,
    StepDependency,
)
from operation.domain.exceptions.domain_exceptions import OptimisticLockConflict
from operation.domain.repositories.i_operation_repository import IOperationRepository
from operation.domain.value_objects.enums import (
    ImpactCeiling,
    OperationClassification,
    OperationRisk,
    OperationState,
    StepState,
    StepType,
)
from operation.domain.value_objects.identifiers import (
    EngagementId,
    ExecutionStepId,
    OperationApprovalId,
    OperationId,
    OperationObjectiveId,
    StepDependencyId,
    TenantId,
)
from operation.domain.value_objects.plan_vos import (
    ExecutionWindowConstraint,
    MitreAttackRef,
    RateLimit,
    StepConstraints,
    StepOutputRef,
    StepTargetRef,
    StepTechniqueRef,
)
from operation.infrastructure.persistence.models.operation_models import (
    ExecutionStepModel,
    OperationApprovalModel,
    OperationModel,
    OperationObjectiveModel,
    StepDependencyModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgOperationRepository(IOperationRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _step_to_model(
        self, step: ExecutionStep, operation: Operation
    ) -> ExecutionStepModel:
        return ExecutionStepModel(
            id=step.step_id.value,
            tenant_id=operation.tenant_id.value,
            operation_id=operation.operation_id.value,
            name=step.name,
            step_type=step.step_type.value,
            state=step.state.value,
            impact_ceiling=step.impact_ceiling.value if step.impact_ceiling else None,
            modifies_persistent_state=step.modifies_persistent_state,
            description=step.description,
            constraints_json={
                "max_duration_seconds": step.constraints.max_duration_seconds,
                "rollback_on_failure": step.constraints.rollback_on_failure,
                "continue_on_failure": step.constraints.continue_on_failure,
            },
            technique_json=(
                {
                    "payload_id": step.technique_ref.payload_id,
                    "technique_id": step.technique_ref.technique_id,
                }
                if step.technique_ref
                else None
            ),
            target_asset_id=step.target_ref.asset_id if step.target_ref else None,
            mitre_json=(
                {"technique_id": step.mitre_ref.technique_id, "tactic": step.mitre_ref.tactic}
                if step.mitre_ref
                else None
            ),
            rate_limit_json=(
                {
                    "max_executions": step.rate_limit.max_executions,
                    "window_seconds": step.rate_limit.window_seconds,
                }
                if step.rate_limit
                else None
            ),
            window_json=(
                {
                    "allowed_days": list(step.window.allowed_days),
                    "start_hour": step.window.start_hour,
                    "end_hour": step.window.end_hour,
                }
                if step.window
                else None
            ),
            output_ref=step.output_ref.evidence_ref if step.output_ref else None,
            created_at=operation.created_at,
            updated_at=operation.updated_at,
        )

    def _step_from_model(self, model: ExecutionStepModel) -> ExecutionStep:
        cj = model.constraints_json or {}
        tj = model.technique_json
        mj = model.mitre_json
        rj = model.rate_limit_json
        wj = model.window_json
        return ExecutionStep(
            step_id=ExecutionStepId(model.id),
            name=model.name,
            step_type=StepType(model.step_type),
            state=StepState(model.state),
            constraints=StepConstraints(
                max_duration_seconds=int(cj.get("max_duration_seconds", 60)),
                rollback_on_failure=bool(cj.get("rollback_on_failure", True)),
                continue_on_failure=bool(cj.get("continue_on_failure", False)),
            ),
            technique_ref=(
                StepTechniqueRef(payload_id=tj["payload_id"], technique_id=tj["technique_id"])
                if tj
                else None
            ),
            target_ref=(
                StepTargetRef(asset_id=model.target_asset_id)
                if model.target_asset_id
                else None
            ),
            impact_ceiling=ImpactCeiling(model.impact_ceiling) if model.impact_ceiling else None,
            modifies_persistent_state=model.modifies_persistent_state,
            mitre_ref=(
                MitreAttackRef(technique_id=mj["technique_id"], tactic=mj.get("tactic"))
                if mj
                else None
            ),
            rate_limit=(
                RateLimit(
                    max_executions=int(rj["max_executions"]),
                    window_seconds=int(rj["window_seconds"]),
                )
                if rj
                else None
            ),
            window=(
                ExecutionWindowConstraint(
                    allowed_days=tuple(wj["allowed_days"]),
                    start_hour=int(wj["start_hour"]),
                    end_hour=int(wj["end_hour"]),
                )
                if wj
                else None
            ),
            output_ref=StepOutputRef(evidence_ref=model.output_ref) if model.output_ref else None,
            description=model.description or "",
        )

    async def _load_children(self, operation_id: UUID, tenant_id: TenantId) -> tuple[
        dict[str, ExecutionStep],
        list[StepDependency],
        list[OperationApproval],
        list[OperationObjective],
    ]:
        steps_result = await self._session.execute(
            select(ExecutionStepModel).where(
                ExecutionStepModel.operation_id == operation_id,
                ExecutionStepModel.tenant_id == tenant_id,
            )
        )
        steps = {
            str(m.id): self._step_from_model(m) for m in steps_result.scalars().all()
        }

        deps_result = await self._session.execute(
            select(StepDependencyModel).where(
                StepDependencyModel.operation_id == operation_id,
                StepDependencyModel.tenant_id == tenant_id,
            )
        )
        deps = [
            StepDependency(
                dependency_id=StepDependencyId(m.id),
                from_step_id=ExecutionStepId(m.from_step_id),
                to_step_id=ExecutionStepId(m.to_step_id),
            )
            for m in deps_result.scalars().all()
        ]

        approvals_result = await self._session.execute(
            select(OperationApprovalModel).where(
                OperationApprovalModel.operation_id == operation_id,
                OperationApprovalModel.tenant_id == tenant_id,
            )
        )
        approvals = [
            OperationApproval(
                approval_id=OperationApprovalId(m.id),
                operator_id=m.operator_id,
                authority=m.authority,
                signature=m.signature,
                approved_at=m.approved_at,
            )
            for m in approvals_result.scalars().all()
        ]

        objectives_result = await self._session.execute(
            select(OperationObjectiveModel).where(
                OperationObjectiveModel.operation_id == operation_id,
                OperationObjectiveModel.tenant_id == tenant_id,
            )
        )
        objectives = [
            OperationObjective(
                objective_id=OperationObjectiveId(m.id),
                description=m.description,
                success_criteria=m.success_criteria,
                is_primary=m.is_primary,
            )
            for m in objectives_result.scalars().all()
        ]
        return steps, deps, approvals, objectives

    def _to_domain(
        self,
        model: OperationModel,
        steps: dict[str, ExecutionStep],
        deps: list[StepDependency],
        approvals: list[OperationApproval],
        objectives: list[OperationObjective],
    ) -> Operation:
        return Operation(
            operation_id=OperationId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            engagement_id=EngagementId(model.engagement_id),
            name=model.name,
            classification=OperationClassification(model.classification),
            state=OperationState(model.state),
            risk=OperationRisk(model.risk),
            steps=steps,
            dependencies=deps,
            approvals=approvals,
            objectives=objectives,
            abort_reason=model.abort_reason,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
        )

    async def _replace_children(self, operation: Operation) -> None:
        oid = operation.operation_id.value
        tid = operation.tenant_id.value
        for model_cls in (
            ExecutionStepModel,
            StepDependencyModel,
            OperationApprovalModel,
            OperationObjectiveModel,
        ):
            await self._session.execute(
                delete(model_cls).where(
                    model_cls.operation_id == oid,
                    model_cls.tenant_id == tid,
                )
            )
        for step in operation.steps.values():
            self._session.add(self._step_to_model(step, operation))
        for dep in operation.dependencies:
            self._session.add(
                StepDependencyModel(
                    id=dep.dependency_id.value,
                    tenant_id=tid,
                    operation_id=oid,
                    from_step_id=dep.from_step_id.value,
                    to_step_id=dep.to_step_id.value,
                )
            )
        for approval in operation.approvals:
            self._session.add(
                OperationApprovalModel(
                    id=approval.approval_id.value,
                    tenant_id=tid,
                    operation_id=oid,
                    operator_id=approval.operator_id,
                    authority=approval.authority,
                    signature=approval.signature,
                    approved_at=approval.approved_at,
                )
            )
        for objective in operation.objectives:
            self._session.add(
                OperationObjectiveModel(
                    id=objective.objective_id.value,
                    tenant_id=tid,
                    operation_id=oid,
                    description=objective.description,
                    success_criteria=objective.success_criteria,
                    is_primary=objective.is_primary,
                )
            )

    async def save(self, operation: Operation) -> None:
        existing = await self._session.execute(
            select(OperationModel).where(OperationModel.id == operation.operation_id.value)
        )
        row = existing.scalar_one_or_none()
        if row is None:
            model = OperationModel(
                id=operation.operation_id.value,
                tenant_id=operation.tenant_id.value,
                engagement_id=operation.engagement_id.value,
                name=operation.name,
                classification=operation.classification.value,
                state=operation.state.value,
                risk=operation.risk.value,
                abort_reason=operation.abort_reason,
                created_at=operation.created_at,
                updated_at=operation.updated_at,
                row_version=1,
            )
            self._session.add(model)
            await self._replace_children(operation)
            await self._session.flush()
            operation._version = 1
            return

        if row.tenant_id != operation.tenant_id.value:
            raise OptimisticLockConflict(str(operation.operation_id), 0, row.row_version)
        actual = row.row_version
        if operation.version == actual + 1 or operation.version == actual:
            expected = actual
        else:
            raise OptimisticLockConflict(
                str(operation.operation_id), operation.version, actual
            )
        result = await self._session.execute(
            update(OperationModel)
            .where(
                OperationModel.id == operation.operation_id.value,
                OperationModel.tenant_id == operation.tenant_id.value,
                OperationModel.row_version == expected,
            )
            .values(
                name=operation.name,
                classification=operation.classification.value,
                state=operation.state.value,
                risk=operation.risk.value,
                abort_reason=operation.abort_reason,
                updated_at=operation.updated_at,
                row_version=expected + 1,
            )
            .returning(OperationModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict(
                str(operation.operation_id), expected, actual
            )
        await self._replace_children(operation)
        operation._version = int(new_version)
        await self._session.flush()

    async def find_by_id(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> Operation | None:
        result = await self._session.execute(
            select(OperationModel).where(
                OperationModel.id == operation_id.value,
                OperationModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        if model is None:
            return None
        steps, deps, approvals, objectives = await self._load_children(
            model.id, tenant_id.value
        )
        return self._to_domain(model, steps, deps, approvals, objectives)

    async def find_by_engagement(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Operation]:
        result = await self._session.execute(
            select(OperationModel)
            .where(
                OperationModel.tenant_id == tenant_id.value,
                OperationModel.engagement_id == engagement_id.value,
            )
            .order_by(OperationModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        models = list(result.scalars().all())
        operations: list[Operation] = []
        for model in models:
            steps, deps, approvals, objectives = await self._load_children(
                model.id, tenant_id.value
            )
            operations.append(self._to_domain(model, steps, deps, approvals, objectives))
        return operations
