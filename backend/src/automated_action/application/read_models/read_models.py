from __future__ import annotations

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
