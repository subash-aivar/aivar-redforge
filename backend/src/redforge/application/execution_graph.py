"""Attack Execution Graph — DAG-based execution planning.

Replaces linear attack iteration with a Directed Acyclic Graph (DAG)
that supports parallel branches, conditional execution, dependencies,
fail-fast, and retry semantics.

The ValidationPipeline consumes the ExecutionPlanner which produces
an AttackGraph. The execution engine traverses the graph respecting
dependencies and parallelism.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.attack_library.entity import AttackDefinition


# ─── Value Objects ────────────────────────────────────────────────────────────


@unique
class NodeStatus(StrEnum):
    """Execution status of a graph node."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@unique
class EdgeType(StrEnum):
    """Relationship type between nodes."""

    SEQUENTIAL = "sequential"
    DEPENDENCY = "dependency"
    CONDITIONAL = "conditional"


@unique
class ExecutionMode(StrEnum):
    """How sibling nodes are dispatched."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


@unique
class FailurePolicy(StrEnum):
    """How node failure affects downstream nodes."""

    FAIL_FAST = "fail_fast"
    CONTINUE = "continue"
    SKIP_DEPENDENTS = "skip_dependents"


# ─── Graph Components ─────────────────────────────────────────────────────────


@dataclass
class AttackNode:
    """A single node in the execution graph.

    Represents one attack to execute with its configuration.
    """

    node_id: str
    attack_id: str
    attack_name: str
    group: str = "default"
    status: NodeStatus = NodeStatus.PENDING
    priority: int = 0
    retry_count: int = 0
    max_retries: int = 0
    timeout_seconds: int = 60
    failure_policy: FailurePolicy = FailurePolicy.CONTINUE
    condition: str = ""  # Future: expression for conditional execution
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            NodeStatus.COMPLETED, NodeStatus.FAILED, NodeStatus.SKIPPED
        }

    @property
    def is_ready(self) -> bool:
        return self.status == NodeStatus.READY


@dataclass(frozen=True)
class AttackEdge:
    """A directed edge between two nodes."""

    source_id: str
    target_id: str
    edge_type: EdgeType = EdgeType.SEQUENTIAL

    def __post_init__(self) -> None:
        if self.source_id == self.target_id:
            raise ValueError("Edge cannot connect a node to itself")


@dataclass
class StageGroup:
    """A logical grouping of nodes that share execution semantics."""

    group_id: str
    name: str
    mode: ExecutionMode = ExecutionMode.SEQUENTIAL
    failure_policy: FailurePolicy = FailurePolicy.CONTINUE
    priority: int = 0


# ─── Attack Graph ─────────────────────────────────────────────────────────────


class AttackGraph:
    """Directed Acyclic Graph of attack execution.

    Nodes are attacks. Edges define ordering and dependencies.
    The graph supports parallel branches, conditional paths,
    and fail-fast semantics.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, AttackNode] = {}
        self._edges: list[AttackEdge] = []
        self._groups: dict[str, StageGroup] = {}

    def add_node(self, node: AttackNode) -> None:
        """Add a node to the graph."""
        if node.node_id in self._nodes:
            raise ValueError(f"Node '{node.node_id}' already exists")
        self._nodes[node.node_id] = node

    def add_edge(self, edge: AttackEdge) -> None:
        """Add a directed edge between two nodes."""
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node '{edge.source_id}' not found")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node '{edge.target_id}' not found")
        self._edges.append(edge)

    def add_group(self, group: StageGroup) -> None:
        """Register a stage group."""
        self._groups[group.group_id] = group

    @property
    def nodes(self) -> list[AttackNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[AttackEdge]:
        return list(self._edges)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def get_node(self, node_id: str) -> AttackNode | None:
        return self._nodes.get(node_id)

    def get_ready_nodes(self) -> list[AttackNode]:
        """Return nodes whose dependencies are all satisfied."""
        ready = []
        for node in self._nodes.values():
            if node.status != NodeStatus.PENDING:
                continue
            deps = self._get_dependencies(node.node_id)
            if all(self._nodes[d].is_terminal for d in deps):
                ready.append(node)
        return ready

    def mark_ready(self, node_id: str) -> None:
        """Mark a node as ready for execution."""
        node = self._nodes[node_id]
        node.status = NodeStatus.READY

    def mark_running(self, node_id: str) -> None:
        """Mark a node as currently executing."""
        self._nodes[node_id].status = NodeStatus.RUNNING

    def mark_completed(self, node_id: str) -> None:
        """Mark a node as successfully completed."""
        self._nodes[node_id].status = NodeStatus.COMPLETED

    def mark_failed(self, node_id: str) -> None:
        """Mark a node as failed."""
        node = self._nodes[node_id]
        node.status = NodeStatus.FAILED
        # Skip dependents if policy says so
        if node.failure_policy == FailurePolicy.SKIP_DEPENDENTS:
            self._skip_dependents(node_id)
        elif node.failure_policy == FailurePolicy.FAIL_FAST:
            self._skip_all_pending()

    def mark_skipped(self, node_id: str) -> None:
        """Mark a node as skipped."""
        self._nodes[node_id].status = NodeStatus.SKIPPED

    @property
    def is_complete(self) -> bool:
        """Whether all nodes have reached a terminal state."""
        return all(n.is_terminal for n in self._nodes.values())

    @property
    def completed_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.status == NodeStatus.COMPLETED)

    @property
    def failed_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.status == NodeStatus.FAILED)

    @property
    def skipped_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.status == NodeStatus.SKIPPED)

    def topological_order(self) -> list[str]:
        """Return nodes in valid execution order (topological sort)."""
        in_degree: dict[str, int] = {nid: 0 for nid in self._nodes}
        for edge in self._edges:
            in_degree[edge.target_id] += 1

        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        queue.sort(key=lambda nid: self._nodes[nid].priority, reverse=True)
        result: list[str] = []

        while queue:
            node_id = queue.pop(0)
            result.append(node_id)
            for edge in self._edges:
                if edge.source_id == node_id:
                    in_degree[edge.target_id] -= 1
                    if in_degree[edge.target_id] == 0:
                        queue.append(edge.target_id)
            queue.sort(key=lambda nid: self._nodes[nid].priority, reverse=True)

        if len(result) != len(self._nodes):
            raise ValueError("Graph contains a cycle — not a valid DAG")

        return result

    def critical_path(self) -> list[str]:
        """Return the longest path through the graph (critical path)."""
        topo = self.topological_order()
        dist: dict[str, int] = {nid: 0 for nid in self._nodes}
        prev: dict[str, str | None] = {nid: None for nid in self._nodes}

        for node_id in topo:
            for edge in self._edges:
                if edge.source_id == node_id:
                    new_dist = dist[node_id] + 1
                    if new_dist > dist[edge.target_id]:
                        dist[edge.target_id] = new_dist
                        prev[edge.target_id] = node_id

        # Find the endpoint with max distance
        end = max(dist, key=lambda k: dist[k])
        path: list[str] = []
        current: str | None = end
        while current is not None:
            path.append(current)
            current = prev[current]
        path.reverse()
        return path

    # ─── Private ──────────────────────────────────────────────────────────

    def _get_dependencies(self, node_id: str) -> list[str]:
        """Get all nodes that must complete before this node."""
        return [e.source_id for e in self._edges if e.target_id == node_id]

    def _skip_dependents(self, node_id: str) -> None:
        """Skip all downstream nodes of a failed node."""
        dependents = [e.target_id for e in self._edges if e.source_id == node_id]
        for dep_id in dependents:
            if self._nodes[dep_id].status == NodeStatus.PENDING:
                self._nodes[dep_id].status = NodeStatus.SKIPPED
                self._skip_dependents(dep_id)

    def _skip_all_pending(self) -> None:
        """Skip all remaining pending nodes (fail-fast)."""
        for node in self._nodes.values():
            if node.status == NodeStatus.PENDING:
                node.status = NodeStatus.SKIPPED


# ─── Execution Planner ────────────────────────────────────────────────────────


class ExecutionPlanner:
    """Generates an AttackGraph from a list of attack definitions.

    The planner determines execution order, parallelism, and dependencies
    based on attack metadata (category, priority, etc.).
    """

    def plan(
        self,
        attacks: list[AttackDefinition],
        mode: ExecutionMode = ExecutionMode.SEQUENTIAL,
        failure_policy: FailurePolicy = FailurePolicy.CONTINUE,
    ) -> AttackGraph:
        """Generate an execution graph from attack definitions."""
        graph = AttackGraph()

        if not attacks:
            return graph

        # Create nodes
        for i, attack in enumerate(attacks):
            node = AttackNode(
                node_id=f"node-{i}",
                attack_id=str(attack.id),
                attack_name=attack.name,
                group=str(attack.category),
                priority=i,
                failure_policy=failure_policy,
            )
            graph.add_node(node)

        # Create edges based on execution mode
        if mode == ExecutionMode.SEQUENTIAL:
            for i in range(len(attacks) - 1):
                graph.add_edge(AttackEdge(
                    source_id=f"node-{i}",
                    target_id=f"node-{i + 1}",
                ))
        # PARALLEL: no edges, all nodes can execute simultaneously

        return graph

    def plan_by_category(
        self,
        attacks: list[AttackDefinition],
        parallel_within_category: bool = True,
        failure_policy: FailurePolicy = FailurePolicy.CONTINUE,
    ) -> AttackGraph:
        """Group attacks by category — sequential between groups, parallel within."""
        graph = AttackGraph()

        if not attacks:
            return graph

        # Group attacks by category
        categories: dict[str, list[tuple[int, AttackDefinition]]] = {}
        for i, attack in enumerate(attacks):
            cat = str(attack.category)
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((i, attack))

        # Create nodes
        for i, attack in enumerate(attacks):
            graph.add_node(AttackNode(
                node_id=f"node-{i}",
                attack_id=str(attack.id),
                attack_name=attack.name,
                group=str(attack.category),
                priority=i,
                failure_policy=failure_policy,
            ))

        # Create edges: last node of each category → first node of next
        cat_list = list(categories.keys())
        for ci in range(len(cat_list) - 1):
            current_cat = categories[cat_list[ci]]
            next_cat = categories[cat_list[ci + 1]]
            # Last of current → first of next (sequential between categories)
            last_idx = current_cat[-1][0]
            first_idx = next_cat[0][0]
            graph.add_edge(AttackEdge(
                source_id=f"node-{last_idx}",
                target_id=f"node-{first_idx}",
            ))

            # Sequential within category if not parallel
            if not parallel_within_category:
                for j in range(len(current_cat) - 1):
                    graph.add_edge(AttackEdge(
                        source_id=f"node-{current_cat[j][0]}",
                        target_id=f"node-{current_cat[j + 1][0]}",
                    ))

        # Handle last category internal edges
        if not parallel_within_category:
            last_cat = categories[cat_list[-1]]
            for j in range(len(last_cat) - 1):
                graph.add_edge(AttackEdge(
                    source_id=f"node-{last_cat[j][0]}",
                    target_id=f"node-{last_cat[j + 1][0]}",
                ))

        return graph


# ─── Graph Execution Result ───────────────────────────────────────────────────


@dataclass(frozen=True)
class ExecutionGraphResult:
    """Summary of graph execution."""

    total_nodes: int
    completed: int
    failed: int
    skipped: int
    critical_path_length: int
    execution_order: list[str]

    @classmethod
    def from_graph(cls, graph: AttackGraph) -> ExecutionGraphResult:
        return cls(
            total_nodes=graph.node_count,
            completed=graph.completed_count,
            failed=graph.failed_count,
            skipped=graph.skipped_count,
            critical_path_length=len(graph.critical_path()) if graph.node_count > 0 else 0,
            execution_order=graph.topological_order() if graph.node_count > 0 else [],
        )
