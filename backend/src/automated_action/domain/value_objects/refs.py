from __future__ import annotations

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
