"""campaignexecution value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from campaignexecution.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from campaignexecution.domain.value_objects.identifiers import (
        CampaignTaskId,
    )


@dataclass(frozen=True, slots=True)
class CampaignInstanceRef:
    instance_id: UUID
    campaign_id: UUID
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class TaskGraphVersionRef:
    graph_id: UUID
    version_str: str


@dataclass(frozen=True, slots=True)
class OperationRef:
    """Reference to an M29 Operation created for a task execution."""

    operation_id: UUID
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class PendingApprovalGate:
    """State when execution is waiting at a HumanApprovalTask gate."""

    task_id: CampaignTaskId
    gate_created_at: datetime
    gate_timeout_seconds: int
    required_approver_role: str
    default_on_timeout: str  # "proceed" | "abort"

    def is_timed_out(self, now: datetime) -> bool:
        from datetime import UTC

        if self.gate_created_at.tzinfo is None:
            created = self.gate_created_at.replace(tzinfo=UTC)
        else:
            created = self.gate_created_at
        return (now - created).total_seconds() >= self.gate_timeout_seconds


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Snapshot of campaign safety policy captured at execution initialization."""

    max_concurrent_actions: int
    auto_abort_on_detection: bool
    auto_abort_on_objective_failure: bool
    blast_radius_ceiling: str


@dataclass(frozen=True, slots=True)
class EngagementRef:
    """Reference to M29 engagement for operation dispatch."""

    engagement_id: UUID
    tenant_id: TenantId


@dataclass(slots=True)
class ObjectiveStateMap:
    """Mutable snapshot of objective states during execution.

    Keyed by objective_id (str UUID). Values are objective state strings.
    """

    states: dict[str, str] = field(default_factory=dict)

    def get(self, objective_id: str) -> str | None:
        return self.states.get(objective_id)

    def set(self, objective_id: str, state: str) -> None:
        self.states[objective_id] = state

    def copy(self) -> ObjectiveStateMap:
        return ObjectiveStateMap(states=dict(self.states))


@dataclass(frozen=True, slots=True)
class ActiveBranchPath:
    """Set of CampaignTaskId values currently on the active execution path."""

    task_ids: frozenset[UUID] = frozenset()

    def with_added(self, *ids: UUID) -> ActiveBranchPath:
        return ActiveBranchPath(task_ids=self.task_ids.union(ids))

    def with_removed(self, *ids: UUID) -> ActiveBranchPath:
        return ActiveBranchPath(task_ids=self.task_ids.difference(ids))

    def contains(self, task_id: UUID) -> bool:
        return task_id in self.task_ids
