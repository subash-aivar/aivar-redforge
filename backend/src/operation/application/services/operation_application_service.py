"""OperationApplicationService — Phase 2 planning and authorization use cases."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from operation.application._validation import validate_str, validate_uuid
from operation.application.dtos.operation_dtos import (
    ExecutionPlanVersionDTO,
    ExecutionStepDTO,
    OperationApprovalDTO,
    OperationDTO,
    OperationObjectiveDTO,
    PlanValidationResultDTO,
    StepDependencyDTO,
)
from operation.application.exceptions import ApplicationNotFoundError
from operation.domain.aggregates.execution_plan_version import ExecutionPlanVersion
from operation.domain.aggregates.operation import Operation
from operation.domain.exceptions.domain_exceptions import ConcurrentExecutingPlanError
from operation.domain.services.execution_plan_validator import ExecutionPlanValidator
from operation.domain.value_objects.enums import (
    ExecutionPlanVersionState,
    ImpactCeiling,
    OperationClassification,
    StepType,
)
from operation.domain.value_objects.identifiers import (
    EngagementId,
    ExecutionPlanVersionId,
    ExecutionStepId,
    OperationId,
    TenantId,
)
from operation.domain.value_objects.plan_vos import (
    ExecutionWindowConstraint,
    MitreAttackRef,
    PlanSnapshot,
    RateLimit,
    StepConstraints,
    StepTargetRef,
    StepTechniqueRef,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from operation.application.commands.operation_commands import (
        AddExecutionStep,
        AddStepDependency,
        ApproveOperation,
        CreateOperation,
        QueueOperation,
        RemoveExecutionStep,
        SetOperationObjectives,
        SignExecutionPlan,
        SubmitOperationForApproval,
        ValidateExecutionPlan,
    )
    from operation.application.ports.i_event_publisher import IEventPublisher
    from operation.application.ports.i_unit_of_work import IUnitOfWork
    from operation.application.queries.operation_queries import (
        GetExecutionPlanVersion,
        GetOperation,
        ListOperationsByEngagement,
        ListPlanVersionsByOperation,
    )
    from operation.domain.ports.i_engagement_query_port import IEngagementQueryPort
    from operation.domain.ports.i_vulnerability_query_port import IVulnerabilityQueryPort

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class OperationApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        engagement_query: IEngagementQueryPort,
        vulnerability_query: IVulnerabilityQueryPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._engagement_query = engagement_query
        self._vulnerability_query = vulnerability_query

    async def _publish(self, aggregates: list[Any]) -> None:
        events = []
        for aggregate in aggregates:
            events.extend(aggregate.pop_events())
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    @staticmethod
    def _operation_dto(op: Operation) -> OperationDTO:
        return OperationDTO(
            id=str(op.operation_id),
            tenant_id=str(op.tenant_id),
            engagement_id=str(op.engagement_id),
            name=op.name,
            classification=op.classification.value,
            state=op.state.value,
            risk=op.risk.value,
            steps=tuple(
                ExecutionStepDTO(
                    id=str(s.step_id),
                    name=s.name,
                    step_type=s.step_type.value,
                    state=s.state.value,
                    impact_ceiling=s.impact_ceiling.value if s.impact_ceiling else None,
                    modifies_persistent_state=s.modifies_persistent_state,
                    technique_id=s.technique_ref.technique_id if s.technique_ref else None,
                    target_asset_id=str(s.target_ref.asset_id) if s.target_ref else None,
                )
                for s in op.steps.values()
            ),
            dependencies=tuple(
                StepDependencyDTO(
                    id=str(d.dependency_id),
                    from_step_id=str(d.from_step_id),
                    to_step_id=str(d.to_step_id),
                )
                for d in op.dependencies
            ),
            approvals=tuple(
                OperationApprovalDTO(
                    id=str(a.approval_id),
                    operator_id=str(a.operator_id),
                    authority=a.authority,
                    approved_at=a.approved_at.isoformat(),
                )
                for a in op.approvals
            ),
            objectives=tuple(
                OperationObjectiveDTO(
                    id=str(o.objective_id),
                    description=o.description,
                    success_criteria=o.success_criteria,
                    is_primary=o.is_primary,
                )
                for o in op.objectives
            ),
            abort_reason=op.abort_reason,
            created_at=op.created_at.isoformat(),
            updated_at=op.updated_at.isoformat(),
            version=op.version,
        )

    @staticmethod
    def _plan_version_dto(pv: ExecutionPlanVersion) -> ExecutionPlanVersionDTO:
        return ExecutionPlanVersionDTO(
            id=str(pv.plan_version_id),
            tenant_id=str(pv.tenant_id),
            operation_id=str(pv.operation_id),
            version_number=pv.version_number,
            state=pv.state.value,
            plan_hash=pv.plan_hash.value if pv.plan_hash else None,
            signed_by_operator_id=str(pv.signed_by.operator_id) if pv.signed_by else None,
            signed_at=pv.signed_by.signed_at.isoformat() if pv.signed_by else None,
            created_at=pv.created_at.isoformat(),
            updated_at=pv.updated_at.isoformat(),
            version=pv.version,
        )

    @staticmethod
    def _serialize_plan(op: Operation) -> PlanSnapshot:
        payload = {
            "operation_id": str(op.operation_id),
            "steps": [
                {
                    "id": str(s.step_id),
                    "name": s.name,
                    "step_type": s.step_type.value,
                    "impact_ceiling": s.impact_ceiling.value if s.impact_ceiling else None,
                    "modifies_persistent_state": s.modifies_persistent_state,
                    "technique_id": s.technique_ref.technique_id if s.technique_ref else None,
                    "payload_id": s.technique_ref.payload_id if s.technique_ref else None,
                    "target_asset_id": str(s.target_ref.asset_id) if s.target_ref else None,
                    "max_duration_seconds": s.constraints.max_duration_seconds,
                    "rollback_on_failure": s.constraints.rollback_on_failure,
                    "continue_on_failure": s.constraints.continue_on_failure,
                }
                for s in sorted(op.steps.values(), key=lambda x: str(x.step_id))
            ],
            "dependencies": [
                {
                    "id": str(d.dependency_id),
                    "from": str(d.from_step_id),
                    "to": str(d.to_step_id),
                }
                for d in sorted(op.dependencies, key=lambda x: str(x.dependency_id))
            ],
        }
        return PlanSnapshot(json.dumps(payload, sort_keys=True, separators=(",", ":")))

    async def create_operation(self, cmd: CreateOperation) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.engagement_id, "engagement_id")
        validate_str(cmd.name, "name", 256)
        classification = OperationClassification(cmd.classification)
        tenant_id = cmd.tenant_id
        now = _utcnow()
        operation = Operation.create(
            tenant_id=tenant_id,
            engagement_id=EngagementId(cmd.engagement_id),
            name=cmd.name,
            classification=classification,
            now=now,
        )
        async with self._uow_factory() as uow:
            await uow.operations.save(operation)
            await uow.commit()
            await self._publish([operation])
            return self._operation_dto(operation)

    async def add_execution_step(self, cmd: AddExecutionStep) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_str(cmd.name, "name", 256)
        tenant_id = cmd.tenant_id
        now = _utcnow()
        technique_ref = None
        if cmd.technique_payload_id and cmd.technique_id:
            technique_ref = StepTechniqueRef(
                payload_id=cmd.technique_payload_id,
                technique_id=cmd.technique_id,
            )
        target_ref = (
            StepTargetRef(asset_id=cmd.target_asset_id) if cmd.target_asset_id else None
        )
        impact = ImpactCeiling(cmd.impact_ceiling) if cmd.impact_ceiling else None
        mitre = (
            MitreAttackRef(technique_id=cmd.mitre_technique_id, tactic=cmd.mitre_tactic)
            if cmd.mitre_technique_id
            else None
        )
        rate_limit = None
        if cmd.rate_limit_max is not None and cmd.rate_limit_window_seconds is not None:
            rate_limit = RateLimit(
                max_executions=cmd.rate_limit_max,
                window_seconds=cmd.rate_limit_window_seconds,
            )
        window = None
        if (
            cmd.window_allowed_days is not None
            and cmd.window_start_hour is not None
            and cmd.window_end_hour is not None
        ):
            window = ExecutionWindowConstraint(
                allowed_days=cmd.window_allowed_days,
                start_hour=cmd.window_start_hour,
                end_hour=cmd.window_end_hour,
            )
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            op.add_execution_step(
                tenant_id=tenant_id,
                name=cmd.name,
                step_type=StepType(cmd.step_type),
                constraints=StepConstraints(
                    max_duration_seconds=cmd.max_duration_seconds,
                    rollback_on_failure=cmd.rollback_on_failure,
                    continue_on_failure=cmd.continue_on_failure,
                ),
                now=now,
                technique_ref=technique_ref,
                target_ref=target_ref,
                impact_ceiling=impact,
                modifies_persistent_state=cmd.modifies_persistent_state,
                mitre_ref=mitre,
                rate_limit=rate_limit,
                window=window,
                description=cmd.description,
            )
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([op])
            return self._operation_dto(op)

    async def remove_execution_step(self, cmd: RemoveExecutionStep) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_uuid(cmd.step_id, "step_id")
        tenant_id = cmd.tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            op.remove_execution_step(
                tenant_id=tenant_id,
                step_id=ExecutionStepId(cmd.step_id),
                now=now,
            )
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([op])
            return self._operation_dto(op)

    async def add_step_dependency(self, cmd: AddStepDependency) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_uuid(cmd.from_step_id, "from_step_id")
        validate_uuid(cmd.to_step_id, "to_step_id")
        tenant_id = cmd.tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            op.add_dependency(
                tenant_id=tenant_id,
                from_step_id=ExecutionStepId(cmd.from_step_id),
                to_step_id=ExecutionStepId(cmd.to_step_id),
                now=now,
            )
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([op])
            return self._operation_dto(op)

    async def set_objectives(self, cmd: SetOperationObjectives) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        tenant_id = cmd.tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            op.set_objectives(
                tenant_id=tenant_id,
                objectives=list(cmd.objectives),
                now=now,
            )
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([op])
            return self._operation_dto(op)

    async def validate_execution_plan(self, cmd: ValidateExecutionPlan) -> PlanValidationResultDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        tenant_id = cmd.tenant_id
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            # Touch vulnerability ACL (degraded ok) for planning context.
            await self._vulnerability_query.get_attack_surface_context(
                op.engagement_id, tenant_id
            )
            authorized = await self._engagement_query.get_authorized_targets(
                op.engagement_id, tenant_id
            )
            techniques = await self._engagement_query.get_allowed_techniques(
                op.engagement_id, tenant_id
            )
            ExecutionPlanValidator.validate(
                op,
                authorized_targets=authorized,
                allowed_techniques=techniques,
            )
            return PlanValidationResultDTO(
                operation_id=str(op.operation_id),
                valid=True,
                message="Execution plan is valid",
            )

    async def sign_execution_plan(self, cmd: SignExecutionPlan) -> ExecutionPlanVersionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_uuid(cmd.operator_id, "operator_id")
        validate_str(cmd.signature, "signature", 4096)
        tenant_id = cmd.tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            authorized = await self._engagement_query.get_authorized_targets(
                op.engagement_id, tenant_id
            )
            techniques = await self._engagement_query.get_allowed_techniques(
                op.engagement_id, tenant_id
            )
            ExecutionPlanValidator.validate(
                op,
                authorized_targets=authorized,
                allowed_techniques=techniques,
            )
            version_number = await uow.plan_versions.next_version_number(
                op.operation_id, tenant_id
            )
            # Supersede any prior Signed versions that are not Executing/Executed.
            existing = await uow.plan_versions.find_by_operation(op.operation_id, tenant_id)
            for prior in existing:
                if prior.state == ExecutionPlanVersionState.SIGNED:
                    prior.supersede(tenant_id=tenant_id, now=now)
                    await uow.plan_versions.save(prior)

            snapshot = self._serialize_plan(op)
            plan_version = ExecutionPlanVersion.create_draft(
                tenant_id=tenant_id,
                operation_id=op.operation_id,
                version_number=version_number,
                snapshot=snapshot,
                now=now,
            )
            plan_version.sign(
                tenant_id=tenant_id,
                operator_id=cmd.operator_id,
                signature=cmd.signature,
                now=now,
            )
            # Emit plan drafted on operation for event completeness.
            op.record_plan_drafted(tenant_id=tenant_id, now=now)
            await uow.plan_versions.save(plan_version)
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([*existing, plan_version, op])
            return self._plan_version_dto(plan_version)

    async def submit_for_approval(self, cmd: SubmitOperationForApproval) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        tenant_id = cmd.tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            op.submit_for_approval(tenant_id=tenant_id, now=now)
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([op])
            return self._operation_dto(op)

    async def approve_operation(self, cmd: ApproveOperation) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_uuid(cmd.operator_id, "operator_id")
        validate_str(cmd.authority, "authority", 64)
        validate_str(cmd.signature, "signature", 4096)
        tenant_id = cmd.tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            op.approve(
                tenant_id=tenant_id,
                operator_id=cmd.operator_id,
                authority=cmd.authority,
                signature=cmd.signature,
                now=now,
            )
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([op])
            return self._operation_dto(op)

    async def queue_operation(self, cmd: QueueOperation) -> OperationDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        tenant_id = cmd.tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(cmd.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(cmd.operation_id))
            engagement_state = await self._engagement_query.get_engagement_state(
                op.engagement_id, tenant_id
            )
            is_active = await self._engagement_query.is_active(op.engagement_id, tenant_id)
            op.queue(
                tenant_id=tenant_id,
                engagement_is_active=is_active,
                engagement_state=engagement_state,
                now=now,
            )
            await uow.operations.save(op)
            await uow.commit()
            await self._publish([op])
            return self._operation_dto(op)

    async def get_operation(self, query: GetOperation) -> OperationDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.operation_id, "operation_id")
        tenant_id = query.tenant_id
        async with self._uow_factory() as uow:
            op = await uow.operations.find_by_id(OperationId(query.operation_id), tenant_id)
            if op is None:
                raise ApplicationNotFoundError("Operation", str(query.operation_id))
            return self._operation_dto(op)

    async def list_by_engagement(self, query: ListOperationsByEngagement) -> list[OperationDTO]:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.engagement_id, "engagement_id")
        tenant_id = query.tenant_id
        async with self._uow_factory() as uow:
            ops = await uow.operations.find_by_engagement(
                EngagementId(query.engagement_id),
                tenant_id,
                limit=query.limit,
                offset=query.offset,
            )
            return [self._operation_dto(o) for o in ops]

    async def get_plan_version(self, query: GetExecutionPlanVersion) -> ExecutionPlanVersionDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.plan_version_id, "plan_version_id")
        tenant_id = query.tenant_id
        async with self._uow_factory() as uow:
            pv = await uow.plan_versions.find_by_id(
                ExecutionPlanVersionId(query.plan_version_id), tenant_id
            )
            if pv is None:
                raise ApplicationNotFoundError(
                    "ExecutionPlanVersion", str(query.plan_version_id)
                )
            return self._plan_version_dto(pv)

    async def list_plan_versions(
        self, query: ListPlanVersionsByOperation
    ) -> list[ExecutionPlanVersionDTO]:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.operation_id, "operation_id")
        tenant_id = query.tenant_id
        async with self._uow_factory() as uow:
            versions = await uow.plan_versions.find_by_operation(
                OperationId(query.operation_id), tenant_id
            )
            return [self._plan_version_dto(v) for v in versions]

    async def mark_plan_executing(
        self,
        *,
        tenant_id: TenantId,
        plan_version_id: UUID,
    ) -> ExecutionPlanVersionDTO:
        """Enforce single Executing plan per operation (used by later phases)."""
        validate_uuid(tenant_id, "tenant_id")
        validate_uuid(plan_version_id, "plan_version_id")
        tid = tenant_id
        now = _utcnow()
        async with self._uow_factory() as uow:
            pv = await uow.plan_versions.find_by_id(
                ExecutionPlanVersionId(plan_version_id), tid
            )
            if pv is None:
                raise ApplicationNotFoundError("ExecutionPlanVersion", str(plan_version_id))
            existing = await uow.plan_versions.find_executing_for_operation(
                pv.operation_id, tid
            )
            if existing is not None and str(existing.plan_version_id) != str(
                pv.plan_version_id
            ):
                raise ConcurrentExecutingPlanError(str(pv.operation_id))
            pv.mark_executing(tenant_id=tid, now=now)
            await uow.plan_versions.save(pv)
            await uow.commit()
            await self._publish([pv])
            return self._plan_version_dto(pv)

    async def invalidate_plans_referencing_payload(
        self,
        *,
        tenant_id: TenantId,
        payload_id: UUID,
    ) -> int:
        """Supersede SIGNED/EXECUTING plan versions whose snapshot references payload_id."""
        validate_uuid(tenant_id, "tenant_id")
        validate_uuid(payload_id, "payload_id")
        tid = tenant_id
        payload_token = str(payload_id)
        now = _utcnow()
        superseded = 0
        async with self._uow_factory() as uow:
            candidates = await uow.plan_versions.find_referencing_payload(
                tid, payload_token
            )
            changed: list[ExecutionPlanVersion] = []
            for pv in candidates:
                if pv.state not in (
                    ExecutionPlanVersionState.SIGNED,
                    ExecutionPlanVersionState.EXECUTING,
                ):
                    continue
                if payload_token not in pv.snapshot.value:
                    continue
                pv.supersede(tenant_id=tid, now=now)
                await uow.plan_versions.save(pv)
                changed.append(pv)
                superseded += 1
            if changed:
                await uow.commit()
                await self._publish(changed)
            else:
                await uow.commit()
            return superseded
