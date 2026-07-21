"""TaskGraphValidator — validates task graph topology before signing."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import TYPE_CHECKING

from taskgraph.domain.value_objects.enums import TaskCriticality, TaskType

if TYPE_CHECKING:
    from taskgraph.domain.aggregates.task_graph import TaskGraph
    from taskgraph.domain.value_objects.identifiers import CampaignTaskId


class TaskGraphValidator:
    """Validates task graphs before signing using Kahn's algorithm for cycle detection."""

    def validate(self, graph: TaskGraph) -> list[str]:
        """Return a list of validation errors. Empty list means graph is valid."""
        errors: list[str] = []
        errors.extend(self._validate_dependency_refs(graph))
        errors.extend(self._find_cycle(graph))
        errors.extend(self._validate_human_approval_tasks(graph))
        errors.extend(self._validate_barrier_tasks(graph))
        errors.extend(self._validate_rollback_tasks(graph))
        errors.extend(self._validate_critical_path(graph))
        return errors

    def _validate_dependency_refs(self, graph: TaskGraph) -> list[str]:
        errors: list[str] = []
        task_ids = frozenset(t.task_id for t in graph.tasks)
        for dep in graph.dependencies:
            if dep.predecessor_id not in task_ids:
                errors.append(
                    f"Dependency references unknown predecessor task: {dep.predecessor_id}"
                )
            if dep.successor_id not in task_ids:
                errors.append(f"Dependency references unknown successor task: {dep.successor_id}")
        return errors

    def _find_cycle(self, graph: TaskGraph) -> list[str]:
        """Kahn's algorithm — iterative topological sort to detect cycles."""
        task_ids = [t.task_id for t in graph.tasks]
        in_degree: dict[CampaignTaskId, int] = {tid: 0 for tid in task_ids}
        successors: dict[CampaignTaskId, list[CampaignTaskId]] = defaultdict(list)

        for dep in graph.dependencies:
            if dep.predecessor_id in in_degree and dep.successor_id in in_degree:
                in_degree[dep.successor_id] += 1
                successors[dep.predecessor_id].append(dep.successor_id)

        queue: deque[CampaignTaskId] = deque(tid for tid, deg in in_degree.items() if deg == 0)
        visited_count = 0

        while queue:
            node = queue.popleft()
            visited_count += 1
            for successor in successors[node]:
                in_degree[successor] -= 1
                if in_degree[successor] == 0:
                    queue.append(successor)

        if visited_count < len(task_ids):
            cycle_nodes = [str(tid) for tid, deg in in_degree.items() if deg > 0]
            return [f"Cycle detected involving tasks: {', '.join(cycle_nodes)}"]
        return []

    def _compute_critical_path_duration(self, graph: TaskGraph) -> int:
        """Compute total duration of the longest weighted path (critical path)."""
        task_map = {t.task_id: t for t in graph.tasks}
        task_ids = list(task_map.keys())
        in_degree: dict[CampaignTaskId, int] = {tid: 0 for tid in task_ids}
        successors: dict[CampaignTaskId, list[CampaignTaskId]] = defaultdict(list)
        predecessors: dict[CampaignTaskId, list[CampaignTaskId]] = defaultdict(list)

        for dep in graph.dependencies:
            if dep.predecessor_id in in_degree and dep.successor_id in in_degree:
                in_degree[dep.successor_id] += 1
                successors[dep.predecessor_id].append(dep.successor_id)
                predecessors[dep.successor_id].append(dep.predecessor_id)

        queue: deque[CampaignTaskId] = deque(tid for tid, deg in in_degree.items() if deg == 0)
        dist: dict[CampaignTaskId, int] = {tid: task_map[tid].timeout_seconds for tid in task_ids}

        while queue:
            node = queue.popleft()
            for successor in successors[node]:
                candidate = dist[node] + task_map[successor].timeout_seconds
                if candidate > dist[successor]:
                    dist[successor] = candidate
                in_degree[successor] -= 1
                if in_degree[successor] == 0:
                    queue.append(successor)

        return max(dist.values(), default=0)

    def _validate_human_approval_tasks(self, graph: TaskGraph) -> list[str]:
        errors: list[str] = []
        for task in graph.tasks:
            if task.task_type == TaskType.HUMAN_APPROVAL_TASK:
                if task.human_approval_config is None:
                    errors.append(
                        f"HumanApprovalTask '{task.task_id}' missing HumanApprovalTaskConfig"
                    )
                elif task.human_approval_config.gate_timeout_seconds <= 0:
                    errors.append(f"HumanApprovalTask '{task.task_id}' must have timeout > 0")
        return errors

    def _validate_barrier_tasks(self, graph: TaskGraph) -> list[str]:
        errors: list[str] = []
        existing_group_ids = frozenset(
            str(t.task_group_id) for t in graph.tasks if t.task_group_id is not None
        )
        for task in graph.tasks:
            if task.task_type == TaskType.BARRIER_TASK:
                if task.barrier_policy is None:
                    errors.append(f"BarrierTask '{task.task_id}' missing BarrierPolicy")
                elif task.barrier_policy.task_group_id not in existing_group_ids:
                    errors.append(
                        f"BarrierTask '{task.task_id}' references unknown "
                        f"task_group_id '{task.barrier_policy.task_group_id}'"
                    )
        return errors

    def _validate_rollback_tasks(self, graph: TaskGraph) -> list[str]:
        errors: list[str] = []
        task_ids = frozenset(t.task_id for t in graph.tasks)
        for task in graph.tasks:
            if task.task_type == TaskType.ROLLBACK_TASK:
                if task.rollback_task_ref is None:
                    errors.append(f"RollbackTask '{task.task_id}' must have rollback_task_ref set")
                elif task.rollback_task_ref not in task_ids:
                    errors.append(
                        f"RollbackTask '{task.task_id}' references unknown task "
                        f"'{task.rollback_task_ref}'"
                    )
        return errors

    def _validate_critical_path(self, graph: TaskGraph) -> list[str]:
        errors: list[str] = []
        critical_tasks = [t for t in graph.tasks if t.criticality == TaskCriticality.CRITICAL_PATH]
        if not critical_tasks:
            return errors

        # Verify critical path tasks form a connected path from start to terminal
        critical_ids = frozenset(t.task_id for t in critical_tasks)
        critical_deps = [
            d
            for d in graph.dependencies
            if d.predecessor_id in critical_ids and d.successor_id in critical_ids
        ]
        in_degree: dict[CampaignTaskId, int] = {tid: 0 for tid in critical_ids}
        for dep in critical_deps:
            in_degree[dep.successor_id] += 1

        start_nodes = [tid for tid, deg in in_degree.items() if deg == 0]
        if len(start_nodes) != 1:
            errors.append(
                f"CriticalPath tasks must have exactly one start node, found {len(start_nodes)}"
            )
            return errors

        # Check critical path duration does not exceed engagement window
        duration = self._compute_critical_path_duration(graph)
        if duration > graph.engagement_window_seconds:
            errors.append(
                f"Critical path duration {duration}s exceeds "
                f"engagement window {graph.engagement_window_seconds}s"
            )
        return errors
