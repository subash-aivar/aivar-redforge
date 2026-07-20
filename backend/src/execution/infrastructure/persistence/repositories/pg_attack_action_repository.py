"""PgAttackActionRepository — partitioned attack_actions table."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from execution.domain.aggregates.attack_action import AttackAction
from execution.domain.exceptions.domain_exceptions import OptimisticLockConflict
from execution.domain.repositories.i_repositories import IAttackActionRepository
from execution.domain.value_objects.enums import (
    AttackActionState,
    ImpactCeiling,
    KillSwitchArmedState,
    RateLimitDecision,
    ScopeVerificationStatus,
)
from execution.domain.value_objects.execution_vos import (
    ActionHash,
    ActionInput,
    ActionOutputRef,
    ExecutionStepRef,
    OperatorRef,
    SafetyCheckResult,
    TargetRef,
    TechniqueRef,
    WorkerRef,
)
from execution.domain.value_objects.identifiers import (
    AttackActionId,
    EngagementId,
    ExecutionStepId,
    ExecutionWorkerId,
    OperationId,
    OperatorId,
    TargetId,
    TenantId,
)
from execution.infrastructure.persistence.models.execution_models import AttackActionModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_TERMINAL = frozenset(
    {
        AttackActionState.COMPLETED.value,
        AttackActionState.FAILED.value,
        AttackActionState.ABORTED.value,
        AttackActionState.TIMED_OUT.value,
    }
)


class PgAttackActionRepository(IAttackActionRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, action: AttackAction) -> None:
        stmt = select(AttackActionModel).where(
            AttackActionModel.id == action.action_id.value,
            AttackActionModel.execution_timestamp == action.execution_timestamp,
        )
        result = await self._session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing is None:
            model = self._to_model(action)
            model.row_version = 1
            self._session.add(model)
            action._version = 1
            return
        if existing.tenant_id != action.tenant_id.value:
            raise OptimisticLockConflict(str(action.action_id), action.version, -1)
        expected = action.version
        upd = (
            update(AttackActionModel)
            .where(
                AttackActionModel.id == action.action_id.value,
                AttackActionModel.execution_timestamp == action.execution_timestamp,
                AttackActionModel.row_version == expected,
            )
            .values(
                state=action.state.value,
                worker_id=action.worker_ref.worker_id.value if action.worker_ref else None,
                completion_timestamp=action.completion_timestamp,
                output_hash=action.output_ref.output_hash if action.output_ref else None,
                output_storage_ref=(
                    action.output_ref.storage_ref if action.output_ref else None
                ),
                failure_reason=action.failure_reason,
                updated_at=action.updated_at,
                row_version=expected + 1,
            )
        )
        result = await self._session.execute(upd)
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise OptimisticLockConflict(
                str(action.action_id), expected, existing.row_version
            )
        action._version = expected + 1

    async def find_by_id(
        self, action_id: AttackActionId, tenant_id: TenantId
    ) -> AttackAction | None:
        stmt = select(AttackActionModel).where(
            AttackActionModel.id == action_id.value,
            AttackActionModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_by_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AttackAction]:
        stmt = (
            select(AttackActionModel)
            .where(
                AttackActionModel.tenant_id == tenant_id.value,
                AttackActionModel.operation_id == operation_id.value,
            )
            .order_by(AttackActionModel.execution_timestamp.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_non_terminal_by_step(
        self,
        step_id: ExecutionStepId,
        tenant_id: TenantId,
    ) -> AttackAction | None:
        stmt = select(AttackActionModel).where(
            AttackActionModel.tenant_id == tenant_id.value,
            AttackActionModel.step_id == step_id.value,
            AttackActionModel.state.notin_(list(_TERMINAL)),
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_in_flight_by_engagement(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> list[AttackAction]:
        stmt = select(AttackActionModel).where(
            AttackActionModel.tenant_id == tenant_id.value,
            AttackActionModel.engagement_id == engagement_id.value,
            AttackActionModel.state.notin_(list(_TERMINAL)),
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    def _to_model(self, action: AttackAction) -> AttackActionModel:
        return AttackActionModel(
            id=action.action_id.value,
            execution_timestamp=action.execution_timestamp,
            tenant_id=action.tenant_id.value,
            engagement_id=action.engagement_id.value,
            operation_id=action.operation_id.value,
            step_id=action.step_ref.step_id.value,
            target_id=action.target_ref.target_id.value,
            technique_id=action.technique_ref.technique_id,
            technique_category=action.technique_ref.technique_category,
            impact_ceiling=action.technique_ref.impact_ceiling.value,
            operator_id=action.operator_ref.operator_id.value,
            worker_id=action.worker_ref.worker_id.value if action.worker_ref else None,
            state=action.state.value,
            action_hash=action.action_hash.value,
            input_hash=action.input_hash,
            action_input_json=dict(action.action_input.parameters),
            safety_check_json={
                "kill_switch_state": action.safety_check.kill_switch_state.value,
                "scope_status": action.safety_check.scope_status.value,
                "rate_limit_decision": action.safety_check.rate_limit_decision.value,
                "window_permitted": action.safety_check.window_permitted,
                "worker_capability_ok": action.safety_check.worker_capability_ok,
            },
            completion_timestamp=action.completion_timestamp,
            output_hash=action.output_ref.output_hash if action.output_ref else None,
            output_storage_ref=(
                action.output_ref.storage_ref if action.output_ref else None
            ),
            failure_reason=action.failure_reason,
            created_at=action.created_at,
            updated_at=action.updated_at,
            row_version=action.version,
        )

    def _to_domain(self, model: AttackActionModel) -> AttackAction:
        safety = model.safety_check_json
        output = None
        if model.output_hash and model.output_storage_ref:
            output = ActionOutputRef(model.output_hash, model.output_storage_ref)
        return AttackAction(
            action_id=AttackActionId(model.id),
            tenant_id=TenantId(model.tenant_id),
            engagement_id=EngagementId(model.engagement_id),
            operation_id=OperationId(model.operation_id),
            step_ref=ExecutionStepRef(
                ExecutionStepId(model.step_id),
                OperationId(model.operation_id),
                EngagementId(model.engagement_id),
            ),
            target_ref=TargetRef(TargetId(model.target_id)),
            technique_ref=TechniqueRef(
                model.technique_id,
                model.technique_category,
                ImpactCeiling(model.impact_ceiling),
            ),
            operator_ref=OperatorRef(OperatorId(model.operator_id)),
            worker_ref=(
                WorkerRef(ExecutionWorkerId(model.worker_id)) if model.worker_id else None
            ),
            action_input=ActionInput(dict(model.action_input_json)),
            input_hash=model.input_hash,
            action_hash=ActionHash(model.action_hash),
            state=AttackActionState(model.state),
            safety_check=SafetyCheckResult(
                kill_switch_state=KillSwitchArmedState(safety["kill_switch_state"]),
                scope_status=ScopeVerificationStatus(safety["scope_status"]),
                rate_limit_decision=RateLimitDecision(safety["rate_limit_decision"]),
                window_permitted=bool(safety["window_permitted"]),
                worker_capability_ok=bool(safety["worker_capability_ok"]),
            ),
            execution_timestamp=model.execution_timestamp,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
            completion_timestamp=model.completion_timestamp,
            output_ref=output,
            failure_reason=model.failure_reason,
        )
