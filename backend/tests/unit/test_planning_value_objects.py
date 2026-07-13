"""Unit tests for the Attack Planning value objects: PlannedAttackStep,
AttackSequence (dedup/dependency validation), and AttackDependencyGraph
(topological sort, cycle detection, priority-weighted ordering)."""

from __future__ import annotations

import pytest

from redforge.domain.planning.value_objects import (
    AttackDependencyGraph,
    AttackPriority,
    AttackSequence,
    EstimatedCost,
    EstimatedDuration,
    PlannedAttackStep,
    SuccessCriteria,
)
from redforge.shared.identifiers import EntityId


def _step(
    attack_id: EntityId | None = None, order: int = 0, group: str = "g",
    priority: AttackPriority = AttackPriority.MEDIUM,
    depends_on: frozenset[EntityId] = frozenset(),
) -> PlannedAttackStep:
    return PlannedAttackStep(
        attack_id=attack_id or EntityId.generate(), order=order, group=group,
        priority=priority, depends_on=depends_on,
    )


class TestPlannedAttackStep:
    def test_negative_order_raises(self) -> None:
        with pytest.raises(ValueError, match="order"):
            PlannedAttackStep(
                attack_id=EntityId.generate(), order=-1, group="g",
                priority=AttackPriority.LOW,
            )

    def test_self_dependency_raises(self) -> None:
        aid = EntityId.generate()
        with pytest.raises(ValueError, match="itself"):
            PlannedAttackStep(
                attack_id=aid, order=0, group="g", priority=AttackPriority.LOW,
                depends_on=frozenset({aid}),
            )


class TestAttackSequence:
    def test_duplicate_attack_id_raises(self) -> None:
        aid = EntityId.generate()
        with pytest.raises(ValueError, match="duplicate"):
            AttackSequence(steps=(_step(aid, order=0), _step(aid, order=1)))

    def test_unresolved_dependency_raises(self) -> None:
        missing = EntityId.generate()
        with pytest.raises(ValueError, match="not present"):
            AttackSequence(steps=(_step(depends_on=frozenset({missing})),))

    def test_valid_sequence_constructs(self) -> None:
        a = EntityId.generate()
        b = EntityId.generate()
        seq = AttackSequence(steps=(
            _step(a, order=0),
            _step(b, order=1, depends_on=frozenset({a})),
        ))
        assert len(seq) == 2
        assert seq.attack_ids == (a, b)

    def test_groups_preserves_first_seen_order(self) -> None:
        seq = AttackSequence(steps=(
            _step(group="beta", order=0),
            _step(group="alpha", order=1),
            _step(group="beta", order=2),
        ))
        assert seq.groups == ("beta", "alpha")

    def test_steps_in_group(self) -> None:
        target = EntityId.generate()
        seq = AttackSequence(steps=(
            _step(target, group="a", order=0),
            _step(group="b", order=1),
        ))
        in_a = seq.steps_in_group("a")
        assert len(in_a) == 1
        assert in_a[0].attack_id == target


class TestAttackDependencyGraph:
    def test_empty_graph_orders_isolated_nodes(self) -> None:
        a, b = EntityId.generate(), EntityId.generate()
        graph = AttackDependencyGraph()
        order = graph.topological_order(frozenset({a, b}))
        assert set(order) == {a, b}
        assert len(order) == 2

    def test_simple_chain_orders_correctly(self) -> None:
        a, b, c = EntityId.generate(), EntityId.generate(), EntityId.generate()
        # b depends on a, c depends on b
        graph = AttackDependencyGraph(edges=frozenset({(b, a), (c, b)}))
        order = graph.topological_order(frozenset({a, b, c}))
        assert order.index(a) < order.index(b) < order.index(c)

    def test_diamond_dependency_orders_correctly(self) -> None:
        a, b, c, d = (EntityId.generate() for _ in range(4))
        # b, c both depend on a; d depends on both b and c
        graph = AttackDependencyGraph(edges=frozenset({
            (b, a), (c, a), (d, b), (d, c),
        }))
        order = graph.topological_order(frozenset({a, b, c, d}))
        assert order.index(a) < order.index(b)
        assert order.index(a) < order.index(c)
        assert order.index(b) < order.index(d)
        assert order.index(c) < order.index(d)

    def test_direct_cycle_raises(self) -> None:
        a, b = EntityId.generate(), EntityId.generate()
        graph = AttackDependencyGraph(edges=frozenset({(a, b), (b, a)}))
        with pytest.raises(ValueError, match="cycle"):
            graph.topological_order(frozenset({a, b}))

    def test_self_cycle_raises(self) -> None:
        a = EntityId.generate()
        graph = AttackDependencyGraph(edges=frozenset({(a, a)}))
        with pytest.raises(ValueError, match="cycle"):
            graph.topological_order(frozenset({a}))

    def test_transitive_cycle_raises(self) -> None:
        a, b, c = EntityId.generate(), EntityId.generate(), EntityId.generate()
        graph = AttackDependencyGraph(edges=frozenset({(a, b), (b, c), (c, a)}))
        with pytest.raises(ValueError, match="cycle"):
            graph.topological_order(frozenset({a, b, c}))

    def test_unrelated_second_cycle_still_detected(self) -> None:
        """A cycle among a SUBSET of nodes must still be caught even
        when other nodes in the same call are perfectly orderable."""
        a, b = EntityId.generate(), EntityId.generate()
        x, y = EntityId.generate(), EntityId.generate()
        graph = AttackDependencyGraph(edges=frozenset({(a, b), (x, y), (y, x)}))
        with pytest.raises(ValueError, match="cycle"):
            graph.topological_order(frozenset({a, b, x, y}))

    def test_priority_key_breaks_ties(self) -> None:
        """Among simultaneously-ready nodes, priority_key decides order
        — without it, ties are broken alphabetically by ID (nondeterministic
        relative to priority); with it, the lower-key node goes first."""
        a, b = EntityId.generate(), EntityId.generate()
        graph = AttackDependencyGraph()
        # No dependencies between a and b — both ready simultaneously.
        rank = {a: 1, b: 0}
        order = graph.topological_order(frozenset({a, b}), priority_key=lambda n: rank[n])
        assert order == (b, a)

    def test_priority_key_never_violates_dependency(self) -> None:
        """priority_key can only pick among *ready* nodes — it must
        never promote a node ahead of an unmet dependency."""
        a, b = EntityId.generate(), EntityId.generate()
        graph = AttackDependencyGraph(edges=frozenset({(b, a)}))  # b depends on a
        # Even if b is given "higher priority" (lower rank), a must still precede it.
        rank = {a: 5, b: 0}
        order = graph.topological_order(frozenset({a, b}), priority_key=lambda n: rank[n])
        assert order == (a, b)

    def test_depends_on_and_dependents_of(self) -> None:
        a, b = EntityId.generate(), EntityId.generate()
        graph = AttackDependencyGraph(edges=frozenset({(b, a)}))
        assert graph.depends_on(b) == frozenset({a})
        assert graph.dependents_of(a) == frozenset({b})
        assert graph.depends_on(a) == frozenset()

    def test_large_chain_orders_without_error(self) -> None:
        """100-node linear chain — a coarse proxy for 'large taxonomy'
        scale behavior, verifying no accidental O(n^2)-that-times-out
        or recursion-depth issue in the iterative Kahn's implementation."""
        nodes = [EntityId.generate() for _ in range(100)]
        edges = frozenset((nodes[i], nodes[i - 1]) for i in range(1, 100))
        graph = AttackDependencyGraph(edges=edges)
        order = graph.topological_order(frozenset(nodes))
        assert order == tuple(nodes)


class TestEstimatedCostAndDuration:
    def test_negative_cost_fields_raise(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            EstimatedCost(request_estimate=-1)
        with pytest.raises(ValueError, match="non-negative"):
            EstimatedCost(token_estimate=-1)
        with pytest.raises(ValueError, match="non-negative"):
            EstimatedCost(monetary_estimate_usd=-0.01)

    def test_negative_duration_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            EstimatedDuration(seconds=-1)

    def test_defaults_are_zero(self) -> None:
        assert EstimatedCost() == EstimatedCost(0, 0, 0.0)


class TestSuccessCriteria:
    def test_empty_description_raises(self) -> None:
        with pytest.raises(ValueError, match="description"):
            SuccessCriteria(description="")

    def test_negative_minimum_findings_raises(self) -> None:
        with pytest.raises(ValueError, match="minimum_findings"):
            SuccessCriteria(description="x", minimum_findings=-1)
