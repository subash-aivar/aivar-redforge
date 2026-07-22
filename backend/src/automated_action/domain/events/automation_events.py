from __future__ import annotations

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
