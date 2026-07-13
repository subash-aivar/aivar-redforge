"""Unit tests for Attack Execution Graph."""

import pytest

from redforge.application.execution_graph import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    ExecutionGraphResult,
    ExecutionMode,
    ExecutionPlanner,
    FailurePolicy,
    NodeStatus,
)
from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackSeverity,
    AttackTechnique,
)


def _attack(
    name: str = "test-attack", category: AttackCategory = AttackCategory.PROMPT_INJECTION
) -> AttackDefinition:
    a = AttackDefinition.create(
        name=name if len(name) >= 3 else f"atk-{name}",
        display_name=f"Attack: {name}",
        description="test",
        category=category,
        technique=AttackTechnique(technique="Test"),
        severity=AttackSeverity.HIGH,
    )
    a.publish()
    a.collect_events()
    return a


class TestAttackGraph:
    def test_add_nodes(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="Attack 1"))
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="Attack 2"))
        assert g.node_count == 2

    def test_duplicate_node_raises(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        with pytest.raises(ValueError, match="already exists"):
            g.add_node(AttackNode(node_id="n1", attack_id="a2", attack_name="B"))

    def test_add_edge(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.add_edge(AttackEdge(source_id="n1", target_id="n2"))
        assert g.edge_count == 1

    def test_self_edge_raises(self) -> None:
        with pytest.raises(ValueError, match="cannot connect"):
            AttackEdge(source_id="n1", target_id="n1")

    def test_edge_missing_node_raises(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        with pytest.raises(ValueError, match="not found"):
            g.add_edge(AttackEdge(source_id="n1", target_id="n2"))

    def test_topological_order(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.add_node(AttackNode(node_id="n3", attack_id="a3", attack_name="C"))
        g.add_edge(AttackEdge(source_id="n1", target_id="n2"))
        g.add_edge(AttackEdge(source_id="n2", target_id="n3"))
        order = g.topological_order()
        assert order.index("n1") < order.index("n2")
        assert order.index("n2") < order.index("n3")

    def test_critical_path(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.add_node(AttackNode(node_id="n3", attack_id="a3", attack_name="C"))
        g.add_edge(AttackEdge(source_id="n1", target_id="n2"))
        g.add_edge(AttackEdge(source_id="n2", target_id="n3"))
        path = g.critical_path()
        assert path == ["n1", "n2", "n3"]

    def test_get_ready_nodes_no_deps(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        ready = g.get_ready_nodes()
        assert len(ready) == 2  # No deps, both ready

    def test_get_ready_nodes_with_deps(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.add_edge(AttackEdge(source_id="n1", target_id="n2"))
        ready = g.get_ready_nodes()
        assert len(ready) == 1
        assert ready[0].node_id == "n1"

    def test_is_complete(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        assert g.is_complete is False
        g.mark_completed("n1")
        assert g.is_complete is True


class TestFailurePolicies:
    def test_fail_fast_skips_all(self) -> None:
        g = AttackGraph()
        g.add_node(
            AttackNode(
                node_id="n1",
                attack_id="a1",
                attack_name="A",
                failure_policy=FailurePolicy.FAIL_FAST,
            )
        )
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.add_node(AttackNode(node_id="n3", attack_id="a3", attack_name="C"))
        g.mark_failed("n1")
        assert g.get_node("n2").status == NodeStatus.SKIPPED  # type: ignore[union-attr]
        assert g.get_node("n3").status == NodeStatus.SKIPPED  # type: ignore[union-attr]

    def test_skip_dependents(self) -> None:
        g = AttackGraph()
        g.add_node(
            AttackNode(
                node_id="n1",
                attack_id="a1",
                attack_name="A",
                failure_policy=FailurePolicy.SKIP_DEPENDENTS,
            )
        )
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.add_node(AttackNode(node_id="n3", attack_id="a3", attack_name="C"))
        g.add_edge(AttackEdge(source_id="n1", target_id="n2"))
        # n3 has no edge from n1
        g.mark_failed("n1")
        assert g.get_node("n2").status == NodeStatus.SKIPPED  # type: ignore[union-attr]
        assert g.get_node("n3").status == NodeStatus.PENDING  # type: ignore[union-attr]

    def test_continue_on_failure(self) -> None:
        g = AttackGraph()
        g.add_node(
            AttackNode(
                node_id="n1",
                attack_id="a1",
                attack_name="A",
                failure_policy=FailurePolicy.CONTINUE,
            )
        )
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.mark_failed("n1")
        assert g.get_node("n2").status == NodeStatus.PENDING  # type: ignore[union-attr]


class TestExecutionPlanner:
    def test_sequential_plan(self) -> None:
        attacks = [_attack(f"a{i}") for i in range(3)]
        planner = ExecutionPlanner()
        graph = planner.plan(attacks, mode=ExecutionMode.SEQUENTIAL)
        assert graph.node_count == 3
        assert graph.edge_count == 2
        order = graph.topological_order()
        assert order == ["node-0", "node-1", "node-2"]

    def test_parallel_plan(self) -> None:
        attacks = [_attack(f"a{i}") for i in range(3)]
        planner = ExecutionPlanner()
        graph = planner.plan(attacks, mode=ExecutionMode.PARALLEL)
        assert graph.node_count == 3
        assert graph.edge_count == 0  # No dependencies
        ready = graph.get_ready_nodes()
        assert len(ready) == 3

    def test_empty_attacks(self) -> None:
        planner = ExecutionPlanner()
        graph = planner.plan([], mode=ExecutionMode.SEQUENTIAL)
        assert graph.node_count == 0

    def test_plan_by_category(self) -> None:
        attacks = [
            _attack("inj-1", AttackCategory.PROMPT_INJECTION),
            _attack("inj-2", AttackCategory.PROMPT_INJECTION),
            _attack("exfil-1", AttackCategory.DATA_EXFILTRATION),
        ]
        planner = ExecutionPlanner()
        graph = planner.plan_by_category(attacks, parallel_within_category=True)
        assert graph.node_count == 3
        # Edge from last injection → first exfiltration
        assert graph.edge_count == 1

    def test_plan_with_failure_policy(self) -> None:
        attacks = [_attack("a1")]
        planner = ExecutionPlanner()
        graph = planner.plan(attacks, failure_policy=FailurePolicy.FAIL_FAST)
        node = graph.get_node("node-0")
        assert node is not None
        assert node.failure_policy == FailurePolicy.FAIL_FAST


class TestExecutionGraphResult:
    def test_from_graph(self) -> None:
        g = AttackGraph()
        g.add_node(AttackNode(node_id="n1", attack_id="a1", attack_name="A"))
        g.add_node(AttackNode(node_id="n2", attack_id="a2", attack_name="B"))
        g.add_edge(AttackEdge(source_id="n1", target_id="n2"))
        g.mark_completed("n1")
        g.mark_failed("n2")

        result = ExecutionGraphResult.from_graph(g)
        assert result.total_nodes == 2
        assert result.completed == 1
        assert result.failed == 1
        assert result.critical_path_length == 2
