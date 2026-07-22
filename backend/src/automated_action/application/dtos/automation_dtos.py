from __future__ import annotations

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
