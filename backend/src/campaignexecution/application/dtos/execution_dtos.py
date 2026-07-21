"""Application DTOs for campaignexecution context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class TaskExecutionRecordDTO:
    task_id: str
    state: str
    outcome: str | None
    operation_id: str | None
    dispatched_at: datetime | None
    completed_at: datetime | None
    failure_reason: str | None


@dataclass(frozen=True, slots=True)
class ExecutionDTO:
    execution_id: str
    tenant_id: str
    campaign_instance_id: str
    graph_id: str
    graph_version: str
    state: str
    concurrent_action_count: int
    task_records: list[TaskExecutionRecordDTO]
    pending_approval_gate_task_id: str | None


@dataclass(frozen=True, slots=True)
class SafetyMonitorDTO:
    monitor_id: str
    tenant_id: str
    campaign_instance_id: str
    monitor_state: str
    concurrent_action_count: int
    auto_abort_triggered: bool
    max_concurrent_actions: int
