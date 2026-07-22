"""CQRS application service for automated_action BC."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from automated_action.application._auth import require_any
from automated_action.application.commands.automation_commands import (
    AuthorizeAutomationStep,
    CancelExecution,
    RequestRollback,
    TriggerPlaybookExecution,
)
from automated_action.application.dtos.automation_dtos import (
    AutomatedActionRecordDTO,
    AutomationExecutionDTO,
)
from automated_action.application.exceptions import ApplicationNotFoundError
from automated_action.application.ports.lookups import (
    IConnectorExecutionPort,
    IPlaybookLookupPort,
)
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
from automated_action.domain.events.automation_events import (
    AutomatedActionExecuted,
    AutomatedActionFailed,
    AutomatedActionRecorded,
    AutomationRolledBack,
    ExecutionEvidenceCaptured,
    PolicyEvaluationCompleted,
)
from automated_action.domain.services.automation_authorization_service import (
    AutomationAuthorizationService,
)
from automated_action.domain.services.automation_outbox_service import AutomationOutboxService
from automated_action.domain.services.execution_evidence_service import ExecutionEvidenceService
from automated_action.domain.services.execution_metrics_service import ExecutionMetricsService
from automated_action.domain.services.execution_policy_service import (
    ExecutionPolicyService,
    PolicySnapshot,
)
from automated_action.domain.services.rollback_eligibility_service import RollbackEligibilityService
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    ActionOutcome,
    ActionRecordStatus,
    ConnectorFailureMode,
    ExecutionStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomationExecutionId,
    TenantId,
)
from automated_action.domain.value_objects.refs import PlaybookRef, TriggerRef


class AutomationApplicationService:
    def __init__(
        self,
        executions: Any,
        records: Any,
        rollbacks: Any,
        playbook_lookup: IPlaybookLookupPort,
        connector_port: IConnectorExecutionPort,
        event_sink: list[Any] | None = None,
    ) -> None:
        self._executions = executions
        self._records = records
        self._rollbacks = rollbacks
        self._playbooks = playbook_lookup
        self._connectors = connector_port
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._authz = AutomationAuthorizationService()
        self._outbox = AutomationOutboxService()
        self._policy = ExecutionPolicyService()
        self._rollback_elig = RollbackEligibilityService()
        self._evidence = ExecutionEvidenceService()
        self.metrics = ExecutionMetricsService()
        self._idempotency: set[str] = set()

    def _tenant(self, value: UUID) -> TenantId:
        return TenantId(value)

    def _dto(self, ex: AutomationExecution) -> AutomationExecutionDTO:
        return AutomationExecutionDTO(
            str(ex.execution_id),
            str(ex.tenant_id),
            ex.playbook_ref.playbook_id,
            ex.status.value,
            ex.current_step,
            ex.total_steps,
            ex.operator_id,
            ex.failure_reason,
        )

    async def trigger(self, cmd: TriggerPlaybookExecution) -> AutomationExecutionDTO:
        require_any(cmd.roles, "automation:operator", "soc:commander", "incident:ciso")
        tenant = self._tenant(cmd.tenant_id)
        pb = await self._playbooks.get_approved_version(
            str(tenant), str(cmd.playbook_id), cmd.version_number
        )
        if pb is None or pb.status != "APPROVED":
            raise ApplicationNotFoundError("approved playbook version not found")
        policy = await self._playbooks.get_policy(str(tenant))
        running = await self._executions.find_by_status(tenant, ExecutionStatus.RUNNING, 1000)
        self._policy.evaluate(
            PolicySnapshot(
                policy.kill_switch_triggered,
                policy.max_concurrent_executions,
                policy.max_actions_per_hour,
            ),
            running_count=len(running),
            actions_last_hour=0,
        )
        self._events.append(
            PolicyEvaluationCompleted(
                tenant_id=str(tenant),
                aggregate_id=str(cmd.playbook_id),
                execution_id="",
                allowed=True,
                reason="ok",
                evaluated_at=datetime.now(UTC).isoformat(),
            )
        )
        idem = f"{cmd.source_event_id}:{cmd.playbook_id}"
        import hashlib

        key = hashlib.sha256(idem.encode()).hexdigest()
        if key in self._idempotency:
            raise ApplicationNotFoundError("duplicate trigger")
        self._idempotency.add(key)
        ex = AutomationExecution.create(
            tenant,
            PlaybookRef(pb.playbook_id, pb.version_number, pb.content_hash),
            TriggerRef(cmd.source_context, cmd.source_event_type, cmd.source_event_id),
            cmd.operator_id,
            len(pb.steps),
            ActionImpactLevel(pb.max_impact_level),
        )
        await self._executions.save(ex, tenant)
        self.metrics.incr("automation.execution.started")
        return self._dto(ex)

    async def run_pending_step_loop(
        self, tenant_id: UUID, execution_id: UUID
    ) -> AutomationExecutionDTO:
        tenant = self._tenant(tenant_id)
        ex = await self._executions.get(AutomationExecutionId(execution_id), tenant)
        if ex is None:
            raise ApplicationNotFoundError("execution not found")
        policy = await self._playbooks.get_policy(str(tenant))
        if policy.kill_switch_triggered and ex.status == ExecutionStatus.PENDING:
            ex.fail("KILL_SWITCH_ACTIVE", None)
            await self._executions.save(ex, tenant)
            self._events.extend(ex.pop_events())
            return self._dto(ex)
        pb = await self._playbooks.get_approved_version(
            str(tenant), ex.playbook_ref.playbook_id, ex.playbook_ref.version_number
        )
        if pb is None:
            ex.fail("PLAYBOOK_MISSING", None)
            await self._executions.save(ex, tenant)
            self._events.extend(ex.pop_events())
            return self._dto(ex)
        if ex.status == ExecutionStatus.PENDING:
            ex.start()
            await self._executions.save(ex, tenant)
            self._events.extend(ex.pop_events())
        steps = sorted(pb.steps, key=lambda s: s.step_number)
        start_idx = ex.current_step
        for step in steps[start_idx:]:
            # kill switch check before each step
            policy = await self._playbooks.get_policy(str(tenant))
            if policy.kill_switch_triggered:
                ex.fail("KILL_SWITCH_ACTIVATED", step.step_number)
                await self._executions.save(ex, tenant)
                self._events.extend(ex.pop_events())
                return self._dto(ex)
            impact = ActionImpactLevel(step.impact_level)
            required = self._authz.runtime_role(impact)
            if required and (
                ex.escalation_request is None
                or ex.escalation_request.resolution is None
                or ex.escalation_request.step_number != step.step_number
            ):
                ex.escalate(step.step_number, impact, required)
                await self._executions.save(ex, tenant)
                self._events.extend(ex.pop_events())
                self.metrics.incr("automation.escalation.pending")
                return self._dto(ex)
            # outbox PENDING first
            record = self._outbox.create_pending(
                tenant,
                ex.execution_id,
                step.step_number,
                step.action_type,
                step.connector_type,
                step.target_selector,
                step.parameters,
            )
            await self._records.append(record, tenant)
            result = await self._connectors.execute(
                str(tenant),
                step.connector_type,
                step.action_type,
                step.parameters,
                f"{ex.execution_id}:{step.step_number}",
            )
            now = datetime.now(UTC)
            if result.success:
                record.complete(
                    ActionOutcome.SUCCESS,
                    result.external_reference,
                    result.duration_ms,
                    rollback_available=result.rollback_available,
                    rollback_parameters_ref=result.rollback_parameters_ref,
                )
                await self._records.update_status(
                    record.record_id,
                    tenant,
                    ActionRecordStatus.COMPLETED,
                    ActionOutcome.SUCCESS,
                    result.external_reference,
                    None,
                    now,
                    result.duration_ms,
                )
                self._events.append(
                    AutomatedActionExecuted(
                        tenant_id=str(tenant),
                        aggregate_id=str(record.record_id),
                        record_id=str(record.record_id),
                        execution_id=str(ex.execution_id),
                        step_number=step.step_number,
                        external_reference=result.external_reference,
                        executed_at=now.isoformat(),
                    )
                )
            else:
                mode = ConnectorFailureMode(result.failure_mode or "SERVER_ERROR")
                record.fail(mode, result.duration_ms)
                await self._records.update_status(
                    record.record_id,
                    tenant,
                    ActionRecordStatus.FAILED,
                    ActionOutcome.FAILURE,
                    None,
                    mode,
                    now,
                    result.duration_ms,
                )
                self._events.append(
                    AutomatedActionFailed(
                        tenant_id=str(tenant),
                        aggregate_id=str(record.record_id),
                        record_id=str(record.record_id),
                        execution_id=str(ex.execution_id),
                        step_number=step.step_number,
                        failure_mode=mode.value,
                        failed_at=now.isoformat(),
                    )
                )
                ex.fail(mode.value, step.step_number)
                await self._executions.save(ex, tenant)
                self._events.extend(ex.pop_events())
                self.metrics.incr("automation.execution.failed")
                return self._dto(ex)
            self._events.append(
                AutomatedActionRecorded(
                    tenant_id=str(tenant),
                    aggregate_id=str(record.record_id),
                    record_id=str(record.record_id),
                    execution_id=str(ex.execution_id),
                    step_number=step.step_number,
                    action_type=step.action_type,
                    connector_type=step.connector_type,
                    target_resource=step.target_selector,
                    outcome=ActionOutcome.SUCCESS.value,
                    recorded_at=now.isoformat(),
                )
            )
            ex.current_step = step.step_number
            await self._executions.save(ex, tenant)
        ex.complete(len(steps), 0)
        await self._executions.save(ex, tenant)
        self._events.extend(ex.pop_events())
        records = await self._records.find_by_execution(ex.execution_id, tenant)
        ev = self._evidence.capture(str(ex.execution_id), [str(r.record_id) for r in records])
        self._events.append(
            ExecutionEvidenceCaptured(
                tenant_id=str(tenant),
                aggregate_id=str(ex.execution_id),
                execution_id=ev.execution_id,
                record_count=len(ev.record_ids),
                captured_at=ev.captured_at.isoformat(),
            )
        )
        self.metrics.incr("automation.execution.completed")
        return self._dto(ex)

    async def authorize_step(self, cmd: AuthorizeAutomationStep) -> AutomationExecutionDTO:
        tenant = self._tenant(cmd.tenant_id)
        ex = await self._executions.get(AutomationExecutionId(cmd.execution_id), tenant)
        if ex is None or ex.escalation_request is None:
            raise ApplicationNotFoundError("escalation not found")
        self._authz.assert_runtime_authorized(
            ex.escalation_request.impact_level,
            cmd.authorizer_roles,
            cmd.authorizer_id,
            ex.operator_id,
        )
        ex.authorize_step(str(cmd.escalation_id), cmd.authorizer_id)
        await self._executions.save(ex, tenant)
        return await self.run_pending_step_loop(cmd.tenant_id, cmd.execution_id)

    async def request_rollback(self, cmd: RequestRollback) -> dict[str, str]:
        require_any(cmd.roles, "soc:commander", "incident:ciso")
        tenant = self._tenant(cmd.tenant_id)
        ex = await self._executions.get(AutomationExecutionId(cmd.execution_id), tenant)
        if ex is None:
            raise ApplicationNotFoundError("execution not found")
        records = await self._records.find_by_execution(ex.execution_id, tenant)
        record = next((r for r in records if r.record_id.value == cmd.record_id), None)
        if record is None or not self._rollback_elig.is_eligible(record):
            raise ApplicationNotFoundError("record not eligible for rollback")
        rb = RollbackRecord.create(tenant, record.record_id, ex.execution_id, cmd.initiated_by)
        await self._rollbacks.append(rb, tenant)
        result = await self._connectors.rollback(
            str(tenant), record.connector_type, record.external_reference or str(record.record_id)
        )
        if result.success:
            rb.mark_completed()
            ex.mark_rolled_back()
        else:
            rb.mark_failed(result.failure_mode or "FAILED")
        await self._rollbacks.update_status(
            rb.rollback_id,
            tenant,
            rb.rollback_status,
            rb.completed_at,
            rb.failure_reason,
        )
        await self._executions.save(ex, tenant)
        self._events.append(
            AutomationRolledBack(
                tenant_id=str(tenant),
                aggregate_id=str(rb.rollback_id),
                execution_id=str(ex.execution_id),
                rollback_id=str(rb.rollback_id),
                original_record_id=str(record.record_id),
                rolled_back_by=cmd.initiated_by,
                rolled_back_at=datetime.now(UTC).isoformat(),
            )
        )
        return {"rollback_id": str(rb.rollback_id), "status": rb.rollback_status.value}

    async def cancel(self, cmd: CancelExecution) -> AutomationExecutionDTO:
        require_any(cmd.roles, "soc:commander", "incident:ciso")
        tenant = self._tenant(cmd.tenant_id)
        ex = await self._executions.get(AutomationExecutionId(cmd.execution_id), tenant)
        if ex is None:
            raise ApplicationNotFoundError("execution not found")
        ex.cancel(cmd.reason)
        await self._executions.save(ex, tenant)
        self._events.extend(ex.pop_events())
        return self._dto(ex)

    async def get(
        self, tenant_id: UUID, execution_id: UUID, roles: tuple[str, ...]
    ) -> AutomationExecutionDTO:
        require_any(roles, "playbook:analyst", "automation:operator", "soc:commander")
        ex = await self._executions.get(
            AutomationExecutionId(execution_id), self._tenant(tenant_id)
        )
        if ex is None:
            raise ApplicationNotFoundError("execution not found")
        return self._dto(ex)

    async def list_executions(
        self,
        tenant_id: UUID,
        roles: tuple[str, ...],
        *,
        status_filter: str | None = None,
        playbook_id_filter: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[AutomationExecutionDTO]:
        require_any(roles, "playbook:analyst", "automation:operator", "soc:commander")
        rows = await self._executions.list(
            self._tenant(tenant_id),
            status_filter=status_filter,
            playbook_id_filter=playbook_id_filter,
            page=page,
            page_size=page_size,
        )
        return [self._dto(r) for r in rows]

    async def action_records(
        self, tenant_id: UUID, execution_id: UUID, roles: tuple[str, ...]
    ) -> list[AutomatedActionRecordDTO]:
        require_any(roles, "playbook:analyst", "soc:commander")
        rows = await self._records.find_by_execution(
            AutomationExecutionId(execution_id), self._tenant(tenant_id)
        )
        return [
            AutomatedActionRecordDTO(
                str(r.record_id),
                str(r.execution_id),
                r.step_number,
                r.action_type,
                r.connector_type,
                r.status.value,
                r.outcome.value if r.outcome else None,
                r.failure_mode.value if r.failure_mode else None,
            )
            for r in rows
        ]

    async def pending_escalations(
        self, tenant_id: UUID, roles: tuple[str, ...]
    ) -> list[AutomationExecutionDTO]:
        require_any(roles, "soc:commander", "incident:ciso", "playbook:analyst")
        rows = await self._executions.find_by_status(
            self._tenant(tenant_id), ExecutionStatus.AWAITING_AUTHORIZATION, 100
        )
        return [self._dto(r) for r in rows]
