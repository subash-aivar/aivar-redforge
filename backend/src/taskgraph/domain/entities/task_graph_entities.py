"""Entities for the TaskGraph domain — nodes and edges of the campaign task graph."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from taskgraph.domain.value_objects.enums import TaskCriticality, TaskType
    from taskgraph.domain.value_objects.identifiers import CampaignTaskId, TaskGroupId
    from taskgraph.domain.value_objects.task_graph_vos import (
        BarrierPolicy,
        ConditionalBranchConfig,
        HumanApprovalTaskConfig,
        RollbackConfiguration,
        TaskOperationTemplate,
    )


class TaskDependency:
    """A directed edge in the task graph."""

    __slots__ = ("condition", "predecessor_id", "successor_id")

    def __init__(
        self,
        predecessor_id: CampaignTaskId,
        successor_id: CampaignTaskId,
        condition: ConditionalBranchConfig,
    ) -> None:
        self.predecessor_id = predecessor_id
        self.successor_id = successor_id
        self.condition = condition


class CampaignTask:
    """A node in the task graph."""

    __slots__ = (
        "barrier_policy",
        "criticality",
        "human_approval_config",
        "name",
        "operation_template",
        "rollback_config",
        "rollback_task_ref",
        "task_group_id",
        "task_id",
        "task_type",
        "timeout_seconds",
    )

    def __init__(
        self,
        task_id: CampaignTaskId,
        task_type: TaskType,
        name: str,
        criticality: TaskCriticality,
        timeout_seconds: int,
        operation_template: TaskOperationTemplate | None = None,
        human_approval_config: HumanApprovalTaskConfig | None = None,
        barrier_policy: BarrierPolicy | None = None,
        rollback_config: RollbackConfiguration | None = None,
        task_group_id: TaskGroupId | None = None,
        rollback_task_ref: CampaignTaskId | None = None,
    ) -> None:
        self.task_id = task_id
        self.task_type = task_type
        self.name = name
        self.criticality = criticality
        self.timeout_seconds = timeout_seconds
        self.operation_template = operation_template
        self.human_approval_config = human_approval_config
        self.barrier_policy = barrier_policy
        self.rollback_config = rollback_config
        self.task_group_id = task_group_id
        self.rollback_task_ref = rollback_task_ref
