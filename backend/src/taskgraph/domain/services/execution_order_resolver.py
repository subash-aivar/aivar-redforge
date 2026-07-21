"""ExecutionOrderResolver — topological sort for campaign task execution scheduling."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from taskgraph.domain.aggregates.task_graph import TaskGraph
    from taskgraph.domain.value_objects.identifiers import CampaignTaskId


class ExecutionOrderResolver:
    """Resolves execution layers and ready tasks using Kahn's topological sort."""

    def resolve(
        self,
        graph: TaskGraph,
        start_task_id: CampaignTaskId | None = None,
    ) -> list[list[CampaignTaskId]]:
        """
        Return ordered execution layers.

        Each inner list is a set of tasks that can execute concurrently (same layer).
        Uses Kahn's algorithm for an iterative (non-recursive) topological sort.

        Example for diamond A→B, A→C, B→D, C→D:  [[A], [B, C], [D]]
        """
        task_ids = [t.task_id for t in graph.tasks]
        if not task_ids:
            return []

        in_degree: dict[CampaignTaskId, int] = {tid: 0 for tid in task_ids}
        successors: dict[CampaignTaskId, list[CampaignTaskId]] = defaultdict(list)

        for dep in graph.dependencies:
            if dep.predecessor_id in in_degree and dep.successor_id in in_degree:
                in_degree[dep.successor_id] += 1
                successors[dep.predecessor_id].append(dep.successor_id)

        # Group tasks that share the same task_group_id into same starting layer
        group_map: dict[str, list[CampaignTaskId]] = defaultdict(list)
        for task in graph.tasks:
            if task.task_group_id is not None:
                group_map[str(task.task_group_id)].append(task.task_id)

        layers: list[list[CampaignTaskId]] = []
        current_layer = [tid for tid, deg in in_degree.items() if deg == 0]

        if start_task_id is not None and start_task_id in in_degree:
            # Filter to only reachable tasks from start_task_id
            reachable = self._reachable_from(start_task_id, successors)
            reachable.add(start_task_id)
            current_layer = [tid for tid in current_layer if tid in reachable]

        while current_layer:
            layers.append(current_layer)
            next_layer: list[CampaignTaskId] = []
            for node in current_layer:
                for successor in successors[node]:
                    in_degree[successor] -= 1
                    if in_degree[successor] == 0:
                        next_layer.append(successor)
            current_layer = next_layer

        return layers

    def _reachable_from(
        self,
        start: CampaignTaskId,
        successors: dict[CampaignTaskId, list[CampaignTaskId]],
    ) -> set[CampaignTaskId]:
        visited: set[CampaignTaskId] = set()
        queue: deque[CampaignTaskId] = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for s in successors.get(node, []):
                if s not in visited:
                    queue.append(s)
        return visited

    def get_ready_tasks(
        self,
        graph: TaskGraph,
        completed_task_ids: frozenset[CampaignTaskId],
        skipped_task_ids: frozenset[CampaignTaskId],
    ) -> list[CampaignTaskId]:
        """
        Return tasks whose all predecessors are completed or skipped,
        and that are not themselves completed or skipped.

        Used at runtime by campaignexecution (Phase 3) to determine next tasks.
        """
        done = completed_task_ids | skipped_task_ids
        task_ids = frozenset(t.task_id for t in graph.tasks)

        predecessors_map: dict[CampaignTaskId, set[CampaignTaskId]] = defaultdict(set)
        for dep in graph.dependencies:
            if dep.predecessor_id in task_ids and dep.successor_id in task_ids:
                predecessors_map[dep.successor_id].add(dep.predecessor_id)

        ready: list[CampaignTaskId] = []
        for task in graph.tasks:
            if task.task_id in done:
                continue
            preds = predecessors_map.get(task.task_id, set())
            if preds.issubset(done):
                ready.append(task.task_id)
        return ready
