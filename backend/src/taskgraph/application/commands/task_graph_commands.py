"""Commands for the TaskGraph application service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateTaskGraphCommand:
    tenant_id: UUID
    name: str
    description: str
    engagement_window_seconds: int


@dataclass(frozen=True, slots=True)
class AddTaskCommand:
    tenant_id: UUID
    graph_id: UUID
    task_type: str
    name: str
    criticality: str
    timeout_seconds: int
    technique_id: str | None = None
    technique_name: str | None = None
    technique_parameters: dict[str, str] | None = None
    human_approval_timeout_seconds: int | None = None
    human_approval_required_role: str | None = None
    human_approval_default_on_timeout: str | None = None
    human_approval_timeout_justification: str | None = None
    barrier_task_group_id: str | None = None
    rollback_task_ref_id: UUID | None = None
    rollback_technique_id: str | None = None
    rollback_not_possible: bool = False
    rollback_not_possible_reason: str | None = None
    task_group_id: str | None = None


@dataclass(frozen=True, slots=True)
class AddDependencyCommand:
    tenant_id: UUID
    graph_id: UUID
    predecessor_task_id: UUID
    successor_task_id: UUID
    predicate: str
    objective_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ValidateTaskGraphCommand:
    tenant_id: UUID
    graph_id: UUID


@dataclass(frozen=True, slots=True)
class SignTaskGraphCommand:
    tenant_id: UUID
    graph_id: UUID
    signed_by: str
    signature: str


@dataclass(frozen=True, slots=True)
class ActivateTaskGraphCommand:
    tenant_id: UUID
    graph_id: UUID


@dataclass(frozen=True, slots=True)
class DeprecateTaskGraphCommand:
    tenant_id: UUID
    graph_id: UUID


@dataclass(frozen=True, slots=True)
class GetTaskGraphQuery:
    tenant_id: UUID
    graph_id: UUID


@dataclass(frozen=True, slots=True)
class GetExecutionOrderQuery:
    tenant_id: UUID
    graph_id: UUID
    start_task_id: UUID | None = None
