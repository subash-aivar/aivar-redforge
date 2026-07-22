"""Generate automated_action bounded context."""

from __future__ import annotations

from .common import FAILURE_MODES, IMPACT, SRC, TESTS, empty_inits, w


def write() -> None:
    base = SRC / "automated_action"
    empty_inits(
        base,
        base / "domain",
        base / "domain" / "aggregates",
        base / "domain" / "entities",
        base / "domain" / "events",
        base / "domain" / "exceptions",
        base / "domain" / "repositories",
        base / "domain" / "services",
        base / "domain" / "value_objects",
        base / "application",
        base / "application" / "commands",
        base / "application" / "dtos",
        base / "application" / "services",
        base / "application" / "ports",
        base / "application" / "read_models",
        base / "infrastructure",
        base / "infrastructure" / "persistence",
        base / "infrastructure" / "workers",
        base / "infrastructure" / "acl",
        base / "infrastructure" / "projectors",
        base / "infrastructure" / "observability",
        base / "api",
        base / "api" / "v1",
    )
    w(base / "__init__.py", '"""M35 automated_action bounded context."""\n')
    w(base / "py.typed", "")
    _domain(base)


def _domain(base):
    w(
        base / "domain" / "value_objects" / "enums.py",
        f'''"""Frozen enums for automated_action BC (M35)."""

from __future__ import annotations

from enum import StrEnum

{IMPACT}
{FAILURE_MODES}

class ExecutionStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    AWAITING_AUTHORIZATION = "AWAITING_AUTHORIZATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    ESCALATED = "ESCALATED"


class ActionRecordStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


class ActionOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


class RollbackStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EscalationResolution(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
''',
    )
    w(
        base / "domain" / "value_objects" / "identifiers.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AutomationExecutionId:
    value: UUID

    @classmethod
    def generate(cls) -> AutomationExecutionId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AutomatedActionRecordId:
    value: UUID

    @classmethod
    def generate(cls) -> AutomatedActionRecordId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RollbackRecordId:
    value: UUID

    @classmethod
    def generate(cls) -> RollbackRecordId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
''',
    )
    w(
        base / "domain" / "value_objects" / "refs.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PlaybookRef:
    playbook_id: str
    version_number: int
    version_content_hash: str


@dataclass(frozen=True, slots=True)
class TriggerRef:
    source_context: str
    source_event_type: str
    source_event_id: str


@dataclass(frozen=True, slots=True)
class ActionEvidence:
    external_reference: str | None
    executed_at: datetime
    duration_ms: int


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    tenant_id: str
    execution_id: str
    operator_id: str
    playbook_id: str


@dataclass(frozen=True, slots=True)
class ExecutionTrace:
    step_number: int
    action_type: str
    status: str
    detail: str


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    success: bool
    steps_completed: int
    steps_failed: int
    failure_reason: str | None


@dataclass(frozen=True, slots=True)
class ExecutionEvidence:
    execution_id: str
    record_ids: tuple[str, ...]
    captured_at: datetime
''',
    )
    w(
        base / "domain" / "exceptions" / "domain_exceptions.py",
        '''from __future__ import annotations


class AutomationDomainError(Exception):
    pass


class DomainInvariantViolation(AutomationDomainError):
    pass


class TenantMismatch(AutomationDomainError):
    pass


class SeparationOfDutiesViolation(AutomationDomainError):
    pass


class KillSwitchActive(AutomationDomainError):
    pass


class PolicyDenied(AutomationDomainError):
    pass


class EscalationTimeout(AutomationDomainError):
    pass


class InvalidExecutionTransition(AutomationDomainError):
    pass
''',
    )
    w(
        base / "domain" / "events" / "base.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseAutomationEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""
''',
    )
    w(
        base / "domain" / "events" / "automation_events.py",
        '''from __future__ import annotations

from dataclasses import dataclass

from automated_action.domain.events.base import BaseAutomationEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationExecutionStarted(BaseAutomationEvent):
    execution_id: str
    playbook_id: str
    playbook_version: int
    trigger_source_context: str
    source_event_id: str
    total_steps: int
    max_impact_level: str
    operator_id: str
    started_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationExecutionCompleted(BaseAutomationEvent):
    execution_id: str
    playbook_id: str
    playbook_version: int
    steps_completed: int
    steps_failed: int
    completed_at: str
    duration_ms: int


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationExecutionFailed(BaseAutomationEvent):
    execution_id: str
    playbook_id: str
    failure_reason: str
    failed_at_step: int | None
    failed_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomatedActionRecorded(BaseAutomationEvent):
    record_id: str
    execution_id: str
    step_number: int
    action_type: str
    connector_type: str
    target_resource: str
    outcome: str
    recorded_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomatedActionExecuted(BaseAutomationEvent):
    record_id: str
    execution_id: str
    step_number: int
    external_reference: str | None
    executed_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomatedActionFailed(BaseAutomationEvent):
    record_id: str
    execution_id: str
    step_number: int
    failure_mode: str
    failed_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationEscalated(BaseAutomationEvent):
    execution_id: str
    escalation_id: str
    step_number: int
    impact_level: str
    required_role: str
    expires_at: str
    escalated_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationRolledBack(BaseAutomationEvent):
    execution_id: str
    rollback_id: str
    original_record_id: str
    rolled_back_by: str
    rolled_back_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionEvidenceCaptured(BaseAutomationEvent):
    execution_id: str
    record_count: int
    captured_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicyEvaluationCompleted(BaseAutomationEvent):
    execution_id: str
    allowed: bool
    reason: str
    evaluated_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionReplayCompleted(BaseAutomationEvent):
    execution_id: str
    replayed_by: str
    completed_at: str
''',
    )
    w(
        base / "domain" / "entities" / "escalation_request.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from automated_action.domain.value_objects.enums import ActionImpactLevel, EscalationResolution


@dataclass
class EscalationRequest:
    escalation_id: UUID
    step_number: int
    impact_level: ActionImpactLevel
    required_role: str
    trigger_operator_id: str
    escalated_at: datetime
    expires_at: datetime
    authorized_by: str | None = None
    authorized_at: datetime | None = None
    resolution: EscalationResolution | None = None

    @classmethod
    def create(
        cls,
        step_number: int,
        impact_level: ActionImpactLevel,
        required_role: str,
        trigger_operator_id: str,
        escalated_at: datetime,
        expires_at: datetime,
    ) -> EscalationRequest:
        return cls(
            uuid4(),
            step_number,
            impact_level,
            required_role,
            trigger_operator_id,
            escalated_at,
            expires_at,
        )
''',
    )
    w(
        base / "domain" / "aggregates" / "automation_execution.py",
        '''"""AutomationExecution aggregate."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from automated_action.domain.entities.escalation_request import EscalationRequest
from automated_action.domain.events.automation_events import (
    AutomationEscalated,
    AutomationExecutionCompleted,
    AutomationExecutionFailed,
    AutomationExecutionStarted,
)
from automated_action.domain.exceptions.domain_exceptions import (
    InvalidExecutionTransition,
    TenantMismatch,
)
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    EscalationResolution,
    ExecutionStatus,
)
from automated_action.domain.value_objects.identifiers import AutomationExecutionId, TenantId
from automated_action.domain.value_objects.refs import PlaybookRef, TriggerRef


class AutomationExecution:
    __slots__ = (
        "_pending_events",
        "completed_at",
        "current_step",
        "escalation_request",
        "execution_id",
        "failure_reason",
        "max_impact_level",
        "operator_id",
        "playbook_ref",
        "started_at",
        "status",
        "tenant_id",
        "total_steps",
        "trigger_ref",
        "version",
    )

    def __init__(
        self,
        execution_id: AutomationExecutionId,
        tenant_id: TenantId,
        playbook_ref: PlaybookRef,
        trigger_ref: TriggerRef,
        status: ExecutionStatus,
        started_at: datetime,
        operator_id: str,
        current_step: int,
        total_steps: int,
        max_impact_level: ActionImpactLevel,
        *,
        completed_at: datetime | None = None,
        escalation_request: EscalationRequest | None = None,
        failure_reason: str | None = None,
        version: int = 1,
    ) -> None:
        self.execution_id = execution_id
        self.tenant_id = tenant_id
        self.playbook_ref = playbook_ref
        self.trigger_ref = trigger_ref
        self.status = status
        self.started_at = started_at
        self.completed_at = completed_at
        self.operator_id = operator_id
        self.current_step = current_step
        self.total_steps = total_steps
        self.max_impact_level = max_impact_level
        self.escalation_request = escalation_request
        self.failure_reason = failure_reason
        self.version = version
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        playbook_ref: PlaybookRef,
        trigger_ref: TriggerRef,
        operator_id: str,
        total_steps: int,
        max_impact_level: ActionImpactLevel,
    ) -> AutomationExecution:
        now = datetime.now(UTC)
        exe = cls(
            AutomationExecutionId.generate(),
            tenant_id,
            playbook_ref,
            trigger_ref,
            ExecutionStatus.PENDING,
            now,
            operator_id,
            0,
            total_steps,
            max_impact_level,
        )
        return exe

    def start(self) -> None:
        if self.status != ExecutionStatus.PENDING:
            raise InvalidExecutionTransition(self.status.value)
        now = datetime.now(UTC)
        self.status = ExecutionStatus.RUNNING
        self.started_at = now
        self.version += 1
        self._pending_events.append(
            AutomationExecutionStarted(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                playbook_id=self.playbook_ref.playbook_id,
                playbook_version=self.playbook_ref.version_number,
                trigger_source_context=self.trigger_ref.source_context,
                source_event_id=self.trigger_ref.source_event_id,
                total_steps=self.total_steps,
                max_impact_level=self.max_impact_level.value,
                operator_id=self.operator_id,
                started_at=now.isoformat(),
            )
        )

    def escalate(self, step_number: int, impact: ActionImpactLevel, required_role: str) -> None:
        now = datetime.now(UTC)
        timeout = timedelta(minutes=30 if impact == ActionImpactLevel.HIGH else 60)
        esc = EscalationRequest.create(
            step_number, impact, required_role, self.operator_id, now, now + timeout
        )
        self.escalation_request = esc
        self.status = ExecutionStatus.AWAITING_AUTHORIZATION
        self.current_step = step_number
        self.version += 1
        self._pending_events.append(
            AutomationEscalated(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                escalation_id=str(esc.escalation_id),
                step_number=step_number,
                impact_level=impact.value,
                required_role=required_role,
                expires_at=esc.expires_at.isoformat(),
                escalated_at=now.isoformat(),
            )
        )

    def authorize_step(self, escalation_id: str, authorizer_id: str) -> None:
        if self.status != ExecutionStatus.AWAITING_AUTHORIZATION or not self.escalation_request:
            raise InvalidExecutionTransition("not awaiting authorization")
        if str(self.escalation_request.escalation_id) != escalation_id:
            raise InvalidExecutionTransition("escalation mismatch")
        now = datetime.now(UTC)
        self.escalation_request.authorized_by = authorizer_id
        self.escalation_request.authorized_at = now
        self.escalation_request.resolution = EscalationResolution.AUTHORIZED
        self.status = ExecutionStatus.RUNNING
        self.version += 1

    def expire_escalation(self) -> None:
        if not self.escalation_request:
            return
        self.escalation_request.resolution = EscalationResolution.EXPIRED
        self.fail("ESCALATION_TIMEOUT", self.escalation_request.step_number)

    def complete(self, steps_completed: int, steps_failed: int = 0) -> None:
        now = datetime.now(UTC)
        self.status = ExecutionStatus.COMPLETED
        self.completed_at = now
        self.current_step = steps_completed
        self.version += 1
        duration = int((now - self.started_at).total_seconds() * 1000)
        self._pending_events.append(
            AutomationExecutionCompleted(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                playbook_id=self.playbook_ref.playbook_id,
                playbook_version=self.playbook_ref.version_number,
                steps_completed=steps_completed,
                steps_failed=steps_failed,
                completed_at=now.isoformat(),
                duration_ms=duration,
            )
        )

    def fail(self, reason: str, failed_at_step: int | None) -> None:
        now = datetime.now(UTC)
        self.status = ExecutionStatus.FAILED
        self.failure_reason = reason
        self.completed_at = now
        self.version += 1
        self._pending_events.append(
            AutomationExecutionFailed(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.execution_id),
                execution_id=str(self.execution_id),
                playbook_id=self.playbook_ref.playbook_id,
                failure_reason=reason,
                failed_at_step=failed_at_step,
                failed_at=now.isoformat(),
            )
        )

    def cancel(self, reason: str) -> None:
        self.fail(f"CANCELLED:{reason}", self.current_step)

    def mark_rolled_back(self) -> None:
        self.status = ExecutionStatus.ROLLED_BACK
        self.completed_at = datetime.now(UTC)
        self.version += 1
''',
    )
    w(
        base / "domain" / "aggregates" / "automated_action_record.py",
        '''"""AutomatedActionRecord — outbox evidence (ADR-M35-002)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json

from automated_action.domain.value_objects.enums import (
    ActionOutcome,
    ActionRecordStatus,
    ConnectorFailureMode,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    TenantId,
)


@dataclass
class AutomatedActionRecord:
    record_id: AutomatedActionRecordId
    tenant_id: TenantId
    execution_id: AutomationExecutionId
    step_number: int
    action_type: str
    connector_type: str
    target_resource: str
    parameters_hash: str
    status: ActionRecordStatus
    outcome: ActionOutcome | None
    external_reference: str | None
    failure_mode: ConnectorFailureMode | None
    attempted_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    rollback_available: bool
    rollback_parameters_ref: str | None

    @staticmethod
    def hash_parameters(parameters: dict[str, object]) -> str:
        payload = json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha256(payload).hexdigest()

    @classmethod
    def create_pending(
        cls,
        tenant_id: TenantId,
        execution_id: AutomationExecutionId,
        step_number: int,
        action_type: str,
        connector_type: str,
        target_resource: str,
        parameters: dict[str, object],
    ) -> AutomatedActionRecord:
        return cls(
            AutomatedActionRecordId.generate(),
            tenant_id,
            execution_id,
            step_number,
            action_type,
            connector_type,
            target_resource,
            cls.hash_parameters(parameters),
            ActionRecordStatus.PENDING,
            None,
            None,
            None,
            datetime.now(UTC),
            None,
            None,
            False,
            None,
        )

    def complete(
        self,
        outcome: ActionOutcome,
        external_reference: str | None,
        duration_ms: int,
        *,
        rollback_available: bool = False,
        rollback_parameters_ref: str | None = None,
    ) -> None:
        self.status = ActionRecordStatus.COMPLETED
        self.outcome = outcome
        self.external_reference = external_reference
        self.completed_at = datetime.now(UTC)
        self.duration_ms = duration_ms
        self.rollback_available = rollback_available
        self.rollback_parameters_ref = rollback_parameters_ref

    def fail(self, failure_mode: ConnectorFailureMode, duration_ms: int) -> None:
        self.status = ActionRecordStatus.FAILED
        self.outcome = ActionOutcome.FAILURE
        self.failure_mode = failure_mode
        self.completed_at = datetime.now(UTC)
        self.duration_ms = duration_ms
''',
    )
    w(
        base / "domain" / "aggregates" / "rollback_record.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from automated_action.domain.value_objects.enums import RollbackStatus
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    RollbackRecordId,
    TenantId,
)


@dataclass
class RollbackRecord:
    rollback_id: RollbackRecordId
    tenant_id: TenantId
    original_record_id: AutomatedActionRecordId
    execution_id: AutomationExecutionId
    rollback_status: RollbackStatus
    initiated_by: str
    initiated_at: datetime
    completed_at: datetime | None
    failure_reason: str | None

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        original_record_id: AutomatedActionRecordId,
        execution_id: AutomationExecutionId,
        initiated_by: str,
    ) -> RollbackRecord:
        return cls(
            RollbackRecordId.generate(),
            tenant_id,
            original_record_id,
            execution_id,
            RollbackStatus.PENDING,
            initiated_by,
            datetime.now(UTC),
            None,
            None,
        )

    def mark_completed(self) -> None:
        self.rollback_status = RollbackStatus.COMPLETED
        self.completed_at = datetime.now(UTC)

    def mark_failed(self, reason: str) -> None:
        self.rollback_status = RollbackStatus.FAILED
        self.failure_reason = reason
        self.completed_at = datetime.now(UTC)
''',
    )
    # Domain services
    for name, content in {
        "automation_authorization_service.py": '''from __future__ import annotations

from automated_action.domain.exceptions.domain_exceptions import (
    SeparationOfDutiesViolation,
)
from automated_action.domain.value_objects.enums import ActionImpactLevel


class AutomationAuthorizationService:
    _RUNTIME = {
        ActionImpactLevel.LOW: None,
        ActionImpactLevel.MEDIUM: None,
        ActionImpactLevel.HIGH: "soc:commander",
        ActionImpactLevel.CRITICAL: "incident:ciso",
    }

    def runtime_role(self, level: ActionImpactLevel) -> str | None:
        return self._RUNTIME[level]

    def assert_runtime_authorized(
        self,
        impact_level: ActionImpactLevel,
        authorizer_roles: tuple[str, ...],
        authorizer_id: str,
        trigger_operator_id: str,
    ) -> None:
        required = self.runtime_role(impact_level)
        if required is None:
            return
        if authorizer_id == trigger_operator_id:
            raise SeparationOfDutiesViolation(
                "Runtime authorizer must differ from the operator who triggered execution"
            )
        if required not in authorizer_roles:
            raise SeparationOfDutiesViolation(f"requires role {required}")
''',
        "rollback_eligibility_service.py": '''from __future__ import annotations

from datetime import UTC, datetime, timedelta

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord


class RollbackEligibilityService:
    def is_eligible(
        self, record: AutomatedActionRecord, *, max_window_hours: int = 24
    ) -> bool:
        if not record.rollback_available:
            return False
        if record.completed_at is None:
            return False
        return datetime.now(UTC) - record.completed_at <= timedelta(hours=max_window_hours)
''',
        "execution_budget_service.py": '''from __future__ import annotations


class ExecutionBudgetService:
    def allows(
        self,
        *,
        running_count: int,
        max_concurrent: int,
        actions_last_hour: int,
        max_actions_per_hour: int,
    ) -> tuple[bool, str]:
        if running_count >= max_concurrent:
            return False, "max_concurrent_executions"
        if actions_last_hour >= max_actions_per_hour:
            return False, "max_actions_per_hour"
        return True, "ok"
''',
        "automation_outbox_service.py": '''from __future__ import annotations

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.value_objects.identifiers import AutomationExecutionId, TenantId


class AutomationOutboxService:
    def create_pending(
        self,
        tenant_id: TenantId,
        execution_id: AutomationExecutionId,
        step_number: int,
        action_type: str,
        connector_type: str,
        target_resource: str,
        parameters: dict[str, object],
    ) -> AutomatedActionRecord:
        return AutomatedActionRecord.create_pending(
            tenant_id,
            execution_id,
            step_number,
            action_type,
            connector_type,
            target_resource,
            parameters,
        )
''',
        "execution_policy_service.py": '''from __future__ import annotations

from dataclasses import dataclass

from automated_action.domain.exceptions.domain_exceptions import KillSwitchActive, PolicyDenied


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    kill_switch_triggered: bool
    max_concurrent_executions: int
    max_actions_per_hour: int
    change_freeze: bool = False
    maintenance_window: bool = False
    business_hours_only: bool = False
    in_business_hours: bool = True


class ExecutionPolicyService:
    def evaluate(
        self,
        policy: PolicySnapshot,
        *,
        running_count: int,
        actions_last_hour: int,
    ) -> None:
        if policy.kill_switch_triggered:
            raise KillSwitchActive("kill switch TRIGGERED")
        if policy.change_freeze:
            raise PolicyDenied("change freeze active")
        if policy.maintenance_window:
            raise PolicyDenied("maintenance window")
        if policy.business_hours_only and not policy.in_business_hours:
            raise PolicyDenied("outside business hours")
        if running_count >= policy.max_concurrent_executions:
            raise PolicyDenied("max concurrent executions")
        if actions_last_hour >= policy.max_actions_per_hour:
            raise PolicyDenied("max actions per hour")
''',
        "execution_evidence_service.py": '''from __future__ import annotations

from datetime import UTC, datetime

from automated_action.domain.value_objects.refs import ExecutionEvidence


class ExecutionEvidenceService:
    def capture(self, execution_id: str, record_ids: list[str]) -> ExecutionEvidence:
        return ExecutionEvidence(execution_id, tuple(record_ids), datetime.now(UTC))
''',
        "execution_replay_service.py": '''from __future__ import annotations

from automated_action.domain.aggregates.automation_execution import AutomationExecution


class ExecutionReplayService:
    def can_replay(self, execution: AutomationExecution) -> bool:
        return execution.status.value in {"FAILED", "COMPLETED"}
''',
        "execution_recovery_service.py": '''from __future__ import annotations

from datetime import UTC, datetime, timedelta

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.value_objects.enums import ActionRecordStatus


class ExecutionRecoveryService:
    def is_stale(self, record: AutomatedActionRecord, *, minutes: int = 5) -> bool:
        if record.status != ActionRecordStatus.PENDING:
            return False
        return datetime.now(UTC) - record.attempted_at > timedelta(minutes=minutes)
''',
        "execution_metrics_service.py": '''from __future__ import annotations


class ExecutionMetricsService:
    def __init__(self) -> None:
        self.counters: dict[str, float] = {}

    def incr(self, name: str, value: float = 1.0) -> None:
        self.counters[name] = self.counters.get(name, 0.0) + value
''',
        "automation_execution_service.py": '''from __future__ import annotations

from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.value_objects.enums import ActionImpactLevel


class AutomationExecutionService:
    def needs_runtime_auth(self, level: ActionImpactLevel) -> bool:
        return level in {ActionImpactLevel.HIGH, ActionImpactLevel.CRITICAL}
''',
    }.items():
        w(base / "domain" / "services" / name, content)

    w(
        base / "domain" / "repositories" / "i_automation_repositories.py",
        '''from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
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


class IAutomationExecutionRepository(ABC):
    @abstractmethod
    async def save(self, execution: AutomationExecution, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def get(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> AutomationExecution | None: ...

    @abstractmethod
    async def find_by_status(
        self, tenant_id: TenantId, status: ExecutionStatus, limit: int
    ) -> list[AutomationExecution]: ...

    @abstractmethod
    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomationExecution]: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId,
        *,
        status_filter: str | None,
        playbook_id_filter: str | None,
        page: int,
        page_size: int,
    ) -> list[AutomationExecution]: ...


class IAutomatedActionRecordRepository(ABC):
    @abstractmethod
    async def append(self, record: AutomatedActionRecord, tenant_id: TenantId) -> None: ...

    @abstractmethod
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
    ) -> None: ...

    @abstractmethod
    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[AutomatedActionRecord]: ...

    @abstractmethod
    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomatedActionRecord]: ...


class IRollbackRecordRepository(ABC):
    @abstractmethod
    async def append(self, record: RollbackRecord, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def update_status(
        self,
        rollback_id: RollbackRecordId,
        tenant_id: TenantId,
        status: RollbackStatus,
        completed_at: datetime | None,
        failure_reason: str | None,
    ) -> None: ...

    @abstractmethod
    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[RollbackRecord]: ...
''',
    )
