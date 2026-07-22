"""automated_action application, infra, API, tests."""

from __future__ import annotations

from .common import SRC, TESTS, w


def write() -> None:
    base = SRC / "automated_action"
    _app(base)
    _infra(base)
    _api(base)
    _tests()


def _app(base):
    w(
        base / "application" / "exceptions.py",
        '''from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationNotFoundError(ApplicationError):
    pass


class ApplicationForbiddenError(ApplicationError):
    pass
''',
    )
    w(
        base / "application" / "_auth.py",
        '''from __future__ import annotations

from automated_action.application.exceptions import ApplicationForbiddenError


def require_any(roles: tuple[str, ...], *allowed: str) -> None:
    if not any(r in roles for r in allowed):
        raise ApplicationForbiddenError(",".join(allowed))
''',
    )
    w(
        base / "application" / "ports" / "lookups.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class PlaybookStepView:
    step_number: int
    action_type: str
    connector_type: str
    target_selector: str
    parameters: dict[str, object]
    impact_level: str


@dataclass(frozen=True, slots=True)
class PlaybookLookupView:
    playbook_id: str
    version_number: int
    content_hash: str
    max_impact_level: str
    status: str
    steps: list[PlaybookStepView]


@dataclass(frozen=True, slots=True)
class PolicyLookupView:
    kill_switch_triggered: bool
    max_concurrent_executions: int
    max_actions_per_hour: int


class IPlaybookLookupPort(Protocol):
    async def get_approved_version(
        self, tenant_id: str, playbook_id: str, version_number: int
    ) -> PlaybookLookupView | None: ...

    async def get_policy(self, tenant_id: str) -> PolicyLookupView: ...


@dataclass(frozen=True, slots=True)
class ConnectorExecResult:
    success: bool
    failure_mode: str | None
    external_reference: str | None
    duration_ms: int
    rollback_available: bool
    rollback_parameters_ref: str | None


class IConnectorExecutionPort(Protocol):
    async def execute(
        self,
        tenant_id: str,
        connector_type: str,
        action_type: str,
        parameters: dict[str, object],
        idempotency_key: str,
    ) -> ConnectorExecResult: ...

    async def verify_outcome(
        self, tenant_id: str, connector_type: str, execution_id: str, step_number: int
    ) -> ConnectorExecResult | None: ...

    async def rollback(
        self, tenant_id: str, connector_type: str, original_action_id: str
    ) -> ConnectorExecResult: ...
''',
    )
    w(
        base / "application" / "commands" / "automation_commands.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class TriggerPlaybookExecution:
    tenant_id: UUID
    playbook_id: UUID
    version_number: int
    source_context: str
    source_event_type: str
    source_event_id: str
    operator_id: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorizeAutomationStep:
    tenant_id: UUID
    execution_id: UUID
    escalation_id: UUID
    authorizer_id: str
    authorizer_roles: tuple[str, ...]
    notes: str | None
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RequestRollback:
    tenant_id: UUID
    execution_id: UUID
    record_id: UUID
    initiated_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CancelExecution:
    tenant_id: UUID
    execution_id: UUID
    cancelled_by: str
    reason: str
    roles: tuple[str, ...]
''',
    )
    w(
        base / "application" / "dtos" / "automation_dtos.py",
        '''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AutomationExecutionDTO:
    execution_id: str
    tenant_id: str
    playbook_id: str
    status: str
    current_step: int
    total_steps: int
    operator_id: str
    failure_reason: str | None


@dataclass(frozen=True, slots=True)
class AutomatedActionRecordDTO:
    record_id: str
    execution_id: str
    step_number: int
    action_type: str
    connector_type: str
    status: str
    outcome: str | None
    failure_mode: str | None
''',
    )
    w(
        base / "application" / "read_models" / "read_models.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class PlaybookEffectivenessReadModel:
    tenant_id: str
    playbook_id: str
    playbook_name: str
    status: str
    total_executions: int
    successful_executions: int
    failed_executions: int
    escalated_executions: int
    avg_execution_duration_ms: float
    avg_mttc_reduction_minutes: float | None
    trigger_count_last_30_days: int
    success_rate_percent: float
    last_triggered_at: datetime | None


@dataclass(frozen=True)
class AutomatedActionHistoryReadModel:
    tenant_id: str
    record_id: str
    execution_id: str
    playbook_name: str
    step_number: int
    action_type: str
    connector_type: str
    target_resource: str
    outcome: str
    failure_mode: str | None
    rollback_status: str | None
    attempted_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    authorized_by: str | None
    trigger_source: str
    trigger_event_id: str


@dataclass(frozen=True)
class PlaybookCoverageReadModel:
    tenant_id: str
    total_detection_rule_types: int
    detection_rule_types_with_playbook: int
    coverage_percent: float
    uncovered_rule_types: list[str]
    total_incident_trigger_types: int
    incident_trigger_types_with_playbook: int
    coverage_by_impact_level: dict[str, int]


@dataclass(frozen=True)
class RollbackTrackingReadModel:
    tenant_id: str
    rollback_id: str
    original_record_id: str
    execution_id: str
    action_type: str
    connector_type: str
    target_resource: str
    rollback_status: str
    initiated_by: str
    initiated_at: datetime
    completed_at: datetime | None
    failure_reason: str | None
    max_rollback_window_expires_at: datetime


@dataclass(frozen=True)
class IntegrationHealthReadModel:
    tenant_id: str
    connector_id: str
    connector_type: str
    display_name: str
    current_status: str
    circuit_state: str
    last_health_check_at: datetime | None
    health_check_success_rate_24h: float
    avg_response_time_ms_24h: float | None
    actions_executed_24h: int
    actions_failed_24h: int
    rate_limit_budget_remaining: int
''',
    )
    w(
        base / "application" / "services" / "automation_application_service.py",
        '''"""CQRS application service for automated_action BC."""

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
    PolicyLookupView,
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
    RollbackStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
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

    async def run_pending_step_loop(self, tenant_id: UUID, execution_id: UUID) -> AutomationExecutionDTO:
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

    async def get(self, tenant_id: UUID, execution_id: UUID, roles: tuple[str, ...]) -> AutomationExecutionDTO:
        require_any(roles, "playbook:analyst", "automation:operator", "soc:commander")
        ex = await self._executions.get(AutomationExecutionId(execution_id), self._tenant(tenant_id))
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
''',
    )


def _infra(base):
    w(
        base / "infrastructure" / "persistence" / "in_memory_repositories.py",
        '''from __future__ import annotations

from datetime import UTC, datetime, timedelta

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
from automated_action.domain.repositories.i_automation_repositories import (
    IAutomatedActionRecordRepository,
    IAutomationExecutionRepository,
    IRollbackRecordRepository,
)
from automated_action.domain.value_objects.enums import (
    ActionOutcome,
    ActionRecordStatus,
    ConnectorFailureMode,
    ExecutionStatus,
    RollbackStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    RollbackRecordId,
    TenantId,
)


class InMemoryAutomationExecutionRepository(IAutomationExecutionRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, AutomationExecution]] = {}

    async def save(self, execution: AutomationExecution, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(execution.execution_id)] = execution

    async def get(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> AutomationExecution | None:
        return self._items.get(str(tenant_id), {}).get(str(execution_id))

    async def find_by_status(
        self, tenant_id: TenantId, status: ExecutionStatus, limit: int
    ) -> list[AutomationExecution]:
        rows = [e for e in self._items.get(str(tenant_id), {}).values() if e.status == status]
        return rows[:limit]

    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomationExecution]:
        cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
        out: list[AutomationExecution] = []
        for tenant_rows in self._items.values():
            for e in tenant_rows.values():
                if e.status == ExecutionStatus.PENDING and e.started_at < cutoff:
                    out.append(e)
        return out

    async def list(
        self,
        tenant_id: TenantId,
        *,
        status_filter: str | None,
        playbook_id_filter: str | None,
        page: int,
        page_size: int,
    ) -> list[AutomationExecution]:
        rows = list(self._items.get(str(tenant_id), {}).values())
        if status_filter:
            rows = [r for r in rows if r.status.value == status_filter]
        if playbook_id_filter:
            rows = [r for r in rows if r.playbook_ref.playbook_id == playbook_id_filter]
        start = (page - 1) * page_size
        return rows[start : start + page_size]


class InMemoryAutomatedActionRecordRepository(IAutomatedActionRecordRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, AutomatedActionRecord]] = {}

    async def append(self, record: AutomatedActionRecord, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(record.record_id)] = record

    async def update_status(
        self,
        record_id: AutomatedActionRecordId,
        tenant_id: TenantId,
        status: ActionRecordStatus,
        outcome: ActionOutcome | None,
        external_reference: str | None,
        failure_mode: ConnectorFailureMode | None,
        completed_at: datetime,
        duration_ms: int,
    ) -> None:
        rec = self._items.get(str(tenant_id), {}).get(str(record_id))
        if rec is None:
            return
        rec.status = status
        rec.outcome = outcome
        rec.external_reference = external_reference
        rec.failure_mode = failure_mode
        rec.completed_at = completed_at
        rec.duration_ms = duration_ms

    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[AutomatedActionRecord]:
        return [
            r
            for r in self._items.get(str(tenant_id), {}).values()
            if r.execution_id.value == execution_id.value
        ]

    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomatedActionRecord]:
        cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
        out: list[AutomatedActionRecord] = []
        for rows in self._items.values():
            for r in rows.values():
                if r.status == ActionRecordStatus.PENDING and r.attempted_at < cutoff:
                    out.append(r)
        return out


class InMemoryRollbackRecordRepository(IRollbackRecordRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, RollbackRecord]] = {}

    async def append(self, record: RollbackRecord, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(record.rollback_id)] = record

    async def update_status(
        self,
        rollback_id: RollbackRecordId,
        tenant_id: TenantId,
        status: RollbackStatus,
        completed_at: datetime | None,
        failure_reason: str | None,
    ) -> None:
        rec = self._items.get(str(tenant_id), {}).get(str(rollback_id))
        if rec is None:
            return
        rec.rollback_status = status
        rec.completed_at = completed_at
        rec.failure_reason = failure_reason

    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[RollbackRecord]:
        return [
            r
            for r in self._items.get(str(tenant_id), {}).values()
            if r.execution_id.value == execution_id.value
        ]
''',
    )
    w(
        base / "infrastructure" / "acl" / "trigger_translators.py",
        '''"""ACL translators — ADR-M35-007. Isolated from upstream domain types."""

from __future__ import annotations

from dataclasses import dataclass

from automated_action.domain.value_objects.refs import TriggerRef


@dataclass(frozen=True, slots=True)
class DetectionFindingEscalatedPayload:
    finding_id: str
    tenant_id: str
    severity: str
    rule_id: str
    asset_ref: str | None
    technique_id: str | None
    escalated_at: str


@dataclass(frozen=True, slots=True)
class IncidentContainedPayload:
    incident_id: str
    tenant_id: str
    severity: str
    contained_at: str


@dataclass(frozen=True, slots=True)
class ExposureThresholdBreachedPayload:
    exposure_id: str
    tenant_id: str
    severity: str
    breached_at: str


@dataclass(frozen=True, slots=True)
class AutomationTriggerEvent:
    source_context: str
    source_event_id: str
    tenant_id: str
    severity_hint: str
    asset_ref: str | None
    source_event_type: str


class M28FindingTriggerTranslator:
    def to_trigger_event(
        self, payload: DetectionFindingEscalatedPayload
    ) -> AutomationTriggerEvent:
        return AutomationTriggerEvent(
            source_context="M28_FINDING",
            source_event_id=payload.finding_id,
            tenant_id=payload.tenant_id,
            severity_hint=payload.severity,
            asset_ref=payload.asset_ref,
            source_event_type="DetectionFindingEscalated",
        )


class M34IncidentTriggerTranslator:
    def to_trigger_event(self, payload: IncidentContainedPayload) -> AutomationTriggerEvent:
        return AutomationTriggerEvent(
            source_context="M34_INCIDENT",
            source_event_id=payload.incident_id,
            tenant_id=payload.tenant_id,
            severity_hint=payload.severity,
            asset_ref=None,
            source_event_type="IncidentContained",
        )


class M32ExposureTriggerTranslator:
    def to_trigger_event(
        self, payload: ExposureThresholdBreachedPayload
    ) -> AutomationTriggerEvent:
        return AutomationTriggerEvent(
            source_context="M32_EXPOSURE",
            source_event_id=payload.exposure_id,
            tenant_id=payload.tenant_id,
            severity_hint=payload.severity,
            asset_ref=None,
            source_event_type="ExposureThresholdBreached",
        )


def to_trigger_ref(event: AutomationTriggerEvent) -> TriggerRef:
    return TriggerRef(event.source_context, event.source_event_type, event.source_event_id)
''',
    )
    w(
        base / "infrastructure" / "projectors" / "kg_projector.py",
        '''from __future__ import annotations

import hashlib
from typing import Any


class InMemorySecurityGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, object]] = {}
        self.edges: set[tuple[str, str, str]] = set()

    def upsert_node(self, node_type: str, domain_id: str, properties: dict[str, object]) -> str:
        node_id = hashlib.sha256(f"{node_type}:{domain_id}".encode()).hexdigest()
        self.nodes[node_id] = {"node_type": node_type, **properties}
        return node_id

    def upsert_edge(self, from_id: str, edge_type: str, to_id: str) -> None:
        self.edges.add((from_id, edge_type, to_id))


class AutomationKGProjector:
    def __init__(self, graph: InMemorySecurityGraph | None = None) -> None:
        self.graph = graph or InMemorySecurityGraph()

    def project(self, event: Any) -> None:
        name = type(event).__name__
        if name == "PlaybookApproved":
            self.graph.upsert_node(
                "playbook",
                event.playbook_id,
                {
                    "tenant_id": event.tenant_id,
                    "status": "APPROVED",
                    "max_impact_level": event.max_impact_level,
                },
            )
        elif name == "AutomatedActionRecorded":
            node = self.graph.upsert_node(
                "automated_action",
                event.record_id,
                {
                    "tenant_id": event.tenant_id,
                    "execution_id": event.execution_id,
                    "action_type": event.action_type,
                    "connector_type": event.connector_type,
                    "outcome": event.outcome,
                },
            )
            playbook_node = hashlib.sha256(
                f"playbook:{getattr(event, 'playbook_id', event.execution_id)}".encode()
            ).hexdigest()
            self.graph.upsert_edge(playbook_node, "executed_action", node)
        elif name == "AutomationRolledBack":
            self.graph.upsert_edge(
                hashlib.sha256(f"automated_action:{event.original_record_id}".encode()).hexdigest(),
                "rolled_back_by",
                hashlib.sha256(f"automated_action:{event.rollback_id}".encode()).hexdigest(),
            )
''',
    )
    w(
        base / "infrastructure" / "projectors" / "analytics_projector.py",
        '''from __future__ import annotations

from typing import Any


class AutomationAnalyticsProjector:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def project(self, event: Any) -> None:
        self.rows.append(
            {
                "event_type": type(event).__name__,
                "tenant_id": getattr(event, "tenant_id", ""),
                "execution_id": getattr(event, "execution_id", ""),
                "payload": event.__dict__ if hasattr(event, "__dict__") else {},
            }
        )
''',
    )
    w(
        base / "infrastructure" / "workers" / "automation_workers.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.domain.value_objects.enums import ActionRecordStatus, ExecutionStatus


class PlaybookTriggerWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def handle(
        self,
        tenant_id: UUID,
        playbook_id: UUID,
        version_number: int,
        source_context: str,
        source_event_type: str,
        source_event_id: str,
        operator_id: str,
        roles: tuple[str, ...],
    ) -> Any:
        self.processed += 1
        return await self._app.trigger(
            TriggerPlaybookExecution(
                tenant_id,
                playbook_id,
                version_number,
                source_context,
                source_event_type,
                source_event_id,
                operator_id,
                roles,
            )
        )


class PlaybookExecutionWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def process(self, tenant_id: UUID, execution_id: UUID) -> Any:
        self.processed += 1
        return await self._app.run_pending_step_loop(tenant_id, execution_id)


class EscalationTimeoutWorker:
    def __init__(self, executions: Any) -> None:
        self._executions = executions
        self.expired = 0

    async def tick(self, tenant_id: UUID) -> int:
        from automated_action.domain.value_objects.identifiers import TenantId

        rows = await self._executions.find_by_status(
            TenantId(tenant_id), ExecutionStatus.AWAITING_AUTHORIZATION, 100
        )
        now = datetime.now(UTC)
        count = 0
        for ex in rows:
            if ex.escalation_request and ex.escalation_request.expires_at < now:
                ex.expire_escalation()
                await self._executions.save(ex, TenantId(tenant_id))
                count += 1
        self.expired += count
        return count


class OutboxRecoveryWorker:
    def __init__(self, records: Any, connector_port: Any) -> None:
        self._records = records
        self._connectors = connector_port
        self.recovered = 0

    async def tick(self) -> int:
        stale = await self._records.find_pending_recovery(5)
        count = 0
        for record in stale:
            verified = await self._connectors.verify_outcome(
                str(record.tenant_id),
                record.connector_type,
                str(record.execution_id),
                record.step_number,
            )
            if verified is None:
                continue
            if verified.success:
                record.complete(
                    __import__(
                        "automated_action.domain.value_objects.enums", fromlist=["ActionOutcome"]
                    ).ActionOutcome.SUCCESS,
                    verified.external_reference,
                    verified.duration_ms,
                )
                await self._records.update_status(
                    record.record_id,
                    record.tenant_id,
                    ActionRecordStatus.COMPLETED,
                    record.outcome,
                    verified.external_reference,
                    None,
                    datetime.now(UTC),
                    verified.duration_ms,
                )
            else:
                from automated_action.domain.value_objects.enums import (
                    ActionOutcome,
                    ConnectorFailureMode,
                )

                mode = ConnectorFailureMode(verified.failure_mode or "SERVER_ERROR")
                record.fail(mode, verified.duration_ms)
                await self._records.update_status(
                    record.record_id,
                    record.tenant_id,
                    ActionRecordStatus.FAILED,
                    ActionOutcome.FAILURE,
                    None,
                    mode,
                    datetime.now(UTC),
                    verified.duration_ms,
                )
            count += 1
        self.recovered += count
        return count


class RetryWorker:
    def __init__(self) -> None:
        self.dead_letters: list[dict[str, object]] = []
        self.ticks = 0

    def tick(self) -> None:
        self.ticks += 1


class RecoveryWorker:
    def __init__(self) -> None:
        self.ticks = 0

    def tick(self) -> None:
        self.ticks += 1


class MetricsWorker:
    def __init__(self, metrics: Any) -> None:
        self._metrics = metrics
        self.ticks = 0

    def tick(self) -> dict[str, float]:
        self.ticks += 1
        return dict(self._metrics.counters)


class ExecutionScheduler:
    def __init__(self, execution_worker: PlaybookExecutionWorker, executions: Any) -> None:
        self.execution_worker = execution_worker
        self._executions = executions

    async def tick(self, tenant_id: UUID) -> int:
        from automated_action.domain.value_objects.identifiers import TenantId

        pending = await self._executions.find_by_status(
            TenantId(tenant_id), ExecutionStatus.PENDING, 50
        )
        for ex in pending:
            await self.execution_worker.process(tenant_id, ex.execution_id.value)
        return len(pending)


class AutomationScheduler:
    def __init__(
        self,
        execution_scheduler: ExecutionScheduler,
        escalation_worker: EscalationTimeoutWorker,
        outbox_worker: OutboxRecoveryWorker,
        retry_worker: RetryWorker,
        recovery_worker: RecoveryWorker,
        metrics_worker: MetricsWorker,
    ) -> None:
        self.execution_scheduler = execution_scheduler
        self.escalation_worker = escalation_worker
        self.outbox_worker = outbox_worker
        self.retry_worker = retry_worker
        self.recovery_worker = recovery_worker
        self.metrics_worker = metrics_worker

    async def tick_all(self, tenant_id: UUID) -> dict[str, int]:
        pending = await self.execution_scheduler.tick(tenant_id)
        expired = await self.escalation_worker.tick(tenant_id)
        recovered = await self.outbox_worker.tick()
        self.retry_worker.tick()
        self.recovery_worker.tick()
        self.metrics_worker.tick()
        return {
            "pending_processed": pending,
            "escalations_expired": expired,
            "outbox_recovered": recovered,
        }
''',
    )
    w(
        base / "infrastructure" / "adapters" / "in_memory_ports.py",
        '''from __future__ import annotations

from automated_action.application.ports.lookups import (
    ConnectorExecResult,
    PlaybookLookupView,
    PlaybookStepView,
    PolicyLookupView,
)


class InMemoryPlaybookLookup:
    def __init__(self) -> None:
        self.playbooks: dict[str, PlaybookLookupView] = {}
        self.policies: dict[str, PolicyLookupView] = {}

    def put(self, view: PlaybookLookupView) -> None:
        self.playbooks[f"{view.playbook_id}:{view.version_number}"] = view

    def put_policy(self, tenant_id: str, policy: PolicyLookupView) -> None:
        self.policies[tenant_id] = policy

    async def get_approved_version(
        self, tenant_id: str, playbook_id: str, version_number: int
    ) -> PlaybookLookupView | None:
        del tenant_id
        return self.playbooks.get(f"{playbook_id}:{version_number}")

    async def get_policy(self, tenant_id: str) -> PolicyLookupView:
        return self.policies.get(
            tenant_id, PolicyLookupView(False, 5, 100)
        )


class InMemoryConnectorExecutionPort:
    def __init__(self) -> None:
        self.fail_next = False
        self.calls: list[str] = []

    async def execute(
        self,
        tenant_id: str,
        connector_type: str,
        action_type: str,
        parameters: dict[str, object],
        idempotency_key: str,
    ) -> ConnectorExecResult:
        del tenant_id, parameters
        self.calls.append(idempotency_key)
        if self.fail_next:
            self.fail_next = False
            return ConnectorExecResult(False, "SERVER_ERROR", None, 5, False, None)
        return ConnectorExecResult(
            True, None, f"ext-{len(self.calls)}", 5, True, f"rb:{connector_type}:{action_type}"
        )

    async def verify_outcome(
        self, tenant_id: str, connector_type: str, execution_id: str, step_number: int
    ) -> ConnectorExecResult | None:
        del tenant_id, connector_type
        return ConnectorExecResult(True, None, f"v-{execution_id}-{step_number}", 1, False, None)

    async def rollback(
        self, tenant_id: str, connector_type: str, original_action_id: str
    ) -> ConnectorExecResult:
        del tenant_id, connector_type
        return ConnectorExecResult(True, None, f"rb-{original_action_id}", 2, False, None)
''',
    )
    # fix path - adapters dir needs init
    w(base / "infrastructure" / "adapters" / "__init__.py", "")
    w(
        base / "infrastructure" / "observability" / "metrics_store.py",
        '''from __future__ import annotations


class OperationalMetricsStore:
    def __init__(self) -> None:
        self._counters: dict[str, float] = {}

    def incr(self, name: str, value: float = 1.0) -> None:
        self._counters[name] = self._counters.get(name, 0.0) + value

    def snapshot(self) -> dict[str, float]:
        return dict(self._counters)
''',
    )
    w(
        base / "infrastructure" / "container.py",
        '''from __future__ import annotations

from automated_action.application.services.automation_application_service import (
    AutomationApplicationService,
)
from automated_action.infrastructure.adapters.in_memory_ports import (
    InMemoryConnectorExecutionPort,
    InMemoryPlaybookLookup,
)
from automated_action.infrastructure.observability.metrics_store import OperationalMetricsStore
from automated_action.infrastructure.persistence.in_memory_repositories import (
    InMemoryAutomatedActionRecordRepository,
    InMemoryAutomationExecutionRepository,
    InMemoryRollbackRecordRepository,
)
from automated_action.infrastructure.projectors.analytics_projector import (
    AutomationAnalyticsProjector,
)
from automated_action.infrastructure.projectors.kg_projector import AutomationKGProjector
from automated_action.infrastructure.workers.automation_workers import (
    AutomationScheduler,
    EscalationTimeoutWorker,
    ExecutionScheduler,
    MetricsWorker,
    OutboxRecoveryWorker,
    PlaybookExecutionWorker,
    PlaybookTriggerWorker,
    RecoveryWorker,
    RetryWorker,
)


class AutomatedActionContainer:
    def __init__(self) -> None:
        self.executions = InMemoryAutomationExecutionRepository()
        self.records = InMemoryAutomatedActionRecordRepository()
        self.rollbacks = InMemoryRollbackRecordRepository()
        self.playbook_lookup = InMemoryPlaybookLookup()
        self.connector_port = InMemoryConnectorExecutionPort()
        self.event_sink: list[object] = []
        self.metrics_store = OperationalMetricsStore()
        self.app = AutomationApplicationService(
            self.executions,
            self.records,
            self.rollbacks,
            self.playbook_lookup,
            self.connector_port,
            self.event_sink,
        )
        self.trigger_worker = PlaybookTriggerWorker(self.app)
        self.execution_worker = PlaybookExecutionWorker(self.app)
        self.escalation_worker = EscalationTimeoutWorker(self.executions)
        self.outbox_worker = OutboxRecoveryWorker(self.records, self.connector_port)
        self.retry_worker = RetryWorker()
        self.recovery_worker = RecoveryWorker()
        self.metrics_worker = MetricsWorker(self.app.metrics)
        self.kg = AutomationKGProjector()
        self.analytics = AutomationAnalyticsProjector()
        self.scheduler = AutomationScheduler(
            ExecutionScheduler(self.execution_worker, self.executions),
            self.escalation_worker,
            self.outbox_worker,
            self.retry_worker,
            self.recovery_worker,
            self.metrics_worker,
        )
''',
    )


def _api(base):
    w(
        base / "api" / "dependencies.py",
        '''from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from automated_action.infrastructure.container import AutomatedActionContainer


def get_container(request: Request) -> AutomatedActionContainer:
    c = getattr(request.app.state, "automated_action_container", None)
    if c is None:
        c = AutomatedActionContainer()
        request.app.state.automated_action_container = c
    return c


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
''',
    )
    w(
        base / "api" / "v1" / "__init__.py",
        "from automated_action.api.v1.routes import router\n\n__all__ = ['router']\n",
    )
    w(
        base / "api" / "v1" / "routes.py",
        '''from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from automated_action.api.dependencies import get_container, roles_header, tenant_id_header
from automated_action.application.commands.automation_commands import (
    AuthorizeAutomationStep,
    CancelExecution,
    RequestRollback,
    TriggerPlaybookExecution,
)
from automated_action.application.exceptions import ApplicationForbiddenError, ApplicationNotFoundError
from automated_action.domain.exceptions.domain_exceptions import AutomationDomainError
from automated_action.infrastructure.container import AutomatedActionContainer

router = APIRouter(tags=["automated-action"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, AutomationDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class TriggerBody(BaseModel):
    playbook_id: UUID
    version_number: int
    source_context: str = "MANUAL"
    source_event_type: str = "manual"
    source_event_id: str
    operator_id: str = "api"


class AuthorizeBody(BaseModel):
    escalation_id: UUID
    authorizer_id: str
    notes: str | None = None


class RollbackBody(BaseModel):
    record_id: UUID
    initiated_by: str = "api"


class CancelBody(BaseModel):
    cancelled_by: str = "api"
    reason: str = "cancelled"


@router.get("/executions")
async def list_executions(
    status_filter: str | None = None,
    playbook_id_filter: str | None = None,
    page: int = 1,
    page_size: int = 50,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.list_executions(
            tenant_id,
            roles,
            status_filter=status_filter,
            playbook_id_filter=playbook_id_filter,
            page=page,
            page_size=page_size,
        )
        return [r.__dict__ for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions", status_code=201)
async def trigger(
    body: TriggerBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.trigger(
            TriggerPlaybookExecution(
                tenant_id,
                body.playbook_id,
                body.version_number,
                body.source_context,
                body.source_event_type,
                body.source_event_id,
                body.operator_id,
                roles,
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return (await container.app.get(tenant_id, execution_id, roles)).__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/executions/{execution_id}/action-records")
async def action_records(
    execution_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.action_records(tenant_id, execution_id, roles)
        return [r.__dict__ for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions/{execution_id}/authorize-step")
async def authorize_step(
    execution_id: UUID,
    body: AuthorizeBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.authorize_step(
            AuthorizeAutomationStep(
                tenant_id,
                execution_id,
                body.escalation_id,
                body.authorizer_id,
                roles,
                body.notes,
                roles,
            )
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions/{execution_id}/rollback")
async def rollback(
    execution_id: UUID,
    body: RollbackBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.request_rollback(
            RequestRollback(tenant_id, execution_id, body.record_id, body.initiated_by, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/executions/{execution_id}/cancel")
async def cancel(
    execution_id: UUID,
    body: CancelBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.cancel(
            CancelExecution(tenant_id, execution_id, body.cancelled_by, body.reason, roles)
        )
        return dto.__dict__
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/executions/pending/escalations")
async def pending_escalations(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutomatedActionContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.pending_escalations(tenant_id, roles)
        return [r.__dict__ for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/automation/metrics")
async def metrics(container: AutomatedActionContainer = Depends(get_container)) -> dict[str, Any]:
    return {
        "counters": container.app.metrics.counters,
        "dead_letters": len(container.retry_worker.dead_letters),
    }
''',
    )


def _tests() -> None:
    tbase = TESTS / "automated_action"
    w(tbase / "__init__.py", "")
    w(
        tbase / "test_architecture.py",
        '''from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "automated_action"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "infrastructure" / "acl").is_dir()
    assert (ROOT / "infrastructure" / "workers").is_dir()


def test_no_cross_context_domain_imports() -> None:
    bad = re.compile(r"from (playbook|integration_hub|detection|incident|engagement|exposure)\\.")
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        if bad.search(p.read_text()):
            raise AssertionError(p)
''',
    )
    w(
        tbase / "test_outbox.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest

from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.domain.value_objects.enums import ActionRecordStatus
from automated_action.infrastructure.container import AutomatedActionContainer
from automated_action.application.commands.automation_commands import TriggerPlaybookExecution


@pytest.mark.asyncio
async def test_outbox_pending_before_complete() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb_id = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb_id),
            1,
            "hash",
            "LOW",
            "APPROVED",
            [
                PlaybookStepView(1, "create_ticket", "ITSM_JIRA", "t", {}, "LOW"),
            ],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb_id, 1, "MANUAL", "manual", "evt-1", "op1", ("automation:operator",)
        )
    )
    done = await c.app.run_pending_step_loop(tenant, __import__("uuid").UUID(ex.execution_id))
    assert done.status == "COMPLETED"
    records = await c.records.find_by_execution(
        c.app._tenant(tenant) and __import__(
            "automated_action.domain.value_objects.identifiers", fromlist=["AutomationExecutionId"]
        ).AutomationExecutionId(__import__("uuid").UUID(ex.execution_id)),
        c.app._tenant(tenant),
    )
    assert records
    assert records[0].status == ActionRecordStatus.COMPLETED
''',
    )
    w(
        tbase / "test_escalation.py",
        '''from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import (
    AuthorizeAutomationStep,
    TriggerPlaybookExecution,
)
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.domain.exceptions.domain_exceptions import SeparationOfDutiesViolation
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_escalation_pause_resume_and_sod() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb_id = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb_id),
            1,
            "h",
            "HIGH",
            "APPROVED",
            [PlaybookStepView(1, "quarantine", "EDR_CROWDSTRIKE", "host", {}, "HIGH")],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb_id, 1, "MANUAL", "manual", "e1", "op1", ("automation:operator",)
        )
    )
    paused = await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    assert paused.status == "AWAITING_AUTHORIZATION"
    loaded = await c.executions.get(
        __import__(
            "automated_action.domain.value_objects.identifiers", fromlist=["AutomationExecutionId"]
        ).AutomationExecutionId(UUID(ex.execution_id)),
        c.app._tenant(tenant),
    )
    assert loaded and loaded.escalation_request
    with pytest.raises(SeparationOfDutiesViolation):
        await c.app.authorize_step(
            AuthorizeAutomationStep(
                tenant,
                UUID(ex.execution_id),
                loaded.escalation_request.escalation_id,
                "op1",
                ("soc:commander",),
                None,
                ("soc:commander",),
            )
        )
    done = await c.app.authorize_step(
        AuthorizeAutomationStep(
            tenant,
            UUID(ex.execution_id),
            loaded.escalation_request.escalation_id,
            "commander2",
            ("soc:commander",),
            "ok",
            ("soc:commander",),
        )
    )
    assert done.status == "COMPLETED"
''',
    )
    w(
        tbase / "test_execution.py",
        '''from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView, PolicyLookupView
from automated_action.domain.exceptions.domain_exceptions import KillSwitchActive
from automated_action.domain.services.execution_policy_service import (
    ExecutionPolicyService,
    PolicySnapshot,
)
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_full_pipeline() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [
                PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW"),
                PlaybookStepView(2, "b", "ITSM_JIRA", "c", {}, "LOW"),
            ],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "evt", "op", ("automation:operator",)
        )
    )
    done = await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    assert done.status == "COMPLETED"
    assert done.current_step == 2


def test_policy_kill_switch() -> None:
    with pytest.raises(KillSwitchActive):
        ExecutionPolicyService().evaluate(
            PolicySnapshot(True, 5, 100), running_count=0, actions_last_hour=0
        )


@pytest.mark.asyncio
async def test_kill_switch_halts_execution() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    c.playbook_lookup.put_policy(str(tenant), PolicyLookupView(True, 5, 100))
    with pytest.raises(KillSwitchActive):
        await c.app.trigger(
            TriggerPlaybookExecution(
                tenant, pb, 1, "MANUAL", "manual", "evt", "op", ("automation:operator",)
            )
        )
''',
    )
    w(
        tbase / "test_rollback.py",
        '''from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import (
    RequestRollback,
    TriggerPlaybookExecution,
)
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_rollback() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "EDR_CROWDSTRIKE", "host", {}, "LOW")],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "e", "op", ("automation:operator",)
        )
    )
    await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    records = await c.app.action_records(tenant, UUID(ex.execution_id), ("playbook:analyst",))
    result = await c.app.request_rollback(
        RequestRollback(
            tenant, UUID(ex.execution_id), UUID(records[0].record_id), "cmd", ("soc:commander",)
        )
    )
    assert result["status"] == "COMPLETED"
''',
    )
    w(
        tbase / "test_acl.py",
        '''from __future__ import annotations

from automated_action.infrastructure.acl.trigger_translators import (
    DetectionFindingEscalatedPayload,
    ExposureThresholdBreachedPayload,
    IncidentContainedPayload,
    M28FindingTriggerTranslator,
    M32ExposureTriggerTranslator,
    M34IncidentTriggerTranslator,
)


def test_m28_translator() -> None:
    event = M28FindingTriggerTranslator().to_trigger_event(
        DetectionFindingEscalatedPayload("f1", "t1", "HIGH", "r1", "a1", "T1059", "2026-01-01T00:00:00Z")
    )
    assert event.source_context == "M28_FINDING"
    assert event.source_event_id == "f1"


def test_m34_translator() -> None:
    event = M34IncidentTriggerTranslator().to_trigger_event(
        IncidentContainedPayload("i1", "t1", "P2_HIGH", "2026-01-01T00:00:00Z")
    )
    assert event.source_context == "M34_INCIDENT"


def test_m32_translator() -> None:
    event = M32ExposureTriggerTranslator().to_trigger_event(
        ExposureThresholdBreachedPayload("e1", "t1", "HIGH", "2026-01-01T00:00:00Z")
    )
    assert event.source_context == "M32_EXPOSURE"
''',
    )
    w(
        tbase / "test_workers.py",
        '''from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_scheduler_processes_pending() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "e", "op", ("automation:operator",)
        )
    )
    result = await c.scheduler.tick_all(tenant)
    assert result["pending_processed"] == 1
''',
    )
    w(
        tbase / "test_api.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from automated_action.api.v1.routes import router
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.infrastructure.container import AutomatedActionContainer


@pytest.mark.asyncio
async def test_trigger_api() -> None:
    app = FastAPI()
    app.include_router(router)
    c = AutomatedActionContainer()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    app.state.automated_action_container = c
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "automation:operator"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/executions",
            json={
                "playbook_id": str(pb),
                "version_number": 1,
                "source_event_id": "e1",
            },
            headers=headers,
        )
        assert r.status_code == 201
''',
    )
    w(
        tbase / "test_domain_unit.py",
        '''from __future__ import annotations

import pytest

from automated_action.domain.services.automation_authorization_service import (
    AutomationAuthorizationService,
)
from automated_action.domain.services.execution_budget_service import ExecutionBudgetService
from automated_action.domain.services.execution_recovery_service import ExecutionRecoveryService
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    ActionRecordStatus,
    ConnectorFailureMode,
    ExecutionStatus,
)
from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.value_objects.identifiers import (
    AutomationExecutionId,
    TenantId,
)
from datetime import UTC, datetime, timedelta
from uuid import uuid4


@pytest.mark.parametrize("level", list(ActionImpactLevel))
def test_impact(level: ActionImpactLevel) -> None:
    assert level.value == level.name


@pytest.mark.parametrize("status", list(ExecutionStatus))
def test_exec_status(status: ExecutionStatus) -> None:
    assert status.value == status.name


@pytest.mark.parametrize("mode", list(ConnectorFailureMode))
def test_failure_mode(mode: ConnectorFailureMode) -> None:
    assert mode.value == mode.name


def test_budget() -> None:
    ok, reason = ExecutionBudgetService().allows(
        running_count=5, max_concurrent=5, actions_last_hour=1, max_actions_per_hour=100
    )
    assert ok is False
    assert reason == "max_concurrent_executions"


def test_recovery_stale() -> None:
    rec = AutomatedActionRecord.create_pending(
        TenantId(uuid4()),
        AutomationExecutionId.generate(),
        1,
        "a",
        "COMM_SLACK",
        "t",
        {},
    )
    rec.attempted_at = datetime.now(UTC) - timedelta(minutes=6)
    assert ExecutionRecoveryService().is_stale(rec) is True
    assert rec.status == ActionRecordStatus.PENDING


def test_runtime_auth_low() -> None:
    AutomationAuthorizationService().assert_runtime_authorized(
        ActionImpactLevel.LOW, (), "a", "b"
    )
''',
    )
