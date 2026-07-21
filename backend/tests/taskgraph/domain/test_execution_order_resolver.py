"""ExecutionOrderResolver tests — topological sort, parallel groups, ready tasks."""

from __future__ import annotations

from taskgraph.domain.services.execution_order_resolver import ExecutionOrderResolver
from taskgraph.domain.value_objects.enums import DependencyPredicate
from taskgraph.domain.value_objects.task_graph_vos import ConditionalBranchConfig
from tests.taskgraph.conftest import make_operation_task, make_task_graph


class TestExecutionOrderResolver:
    def test_linear_graph_single_layer_per_task(self, tenant_id, now) -> None:
        """A→B→C produces [[A], [B], [C]]."""
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        a = make_operation_task("A")
        b = make_operation_task("B")
        c = make_operation_task("C")
        for t in [a, b, c]:
            graph.add_task(tenant_id, t, now)
        cond = ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE)
        graph.add_dependency(tenant_id, a.task_id, b.task_id, cond, now)
        graph.add_dependency(tenant_id, b.task_id, c.task_id, cond, now)

        resolver = ExecutionOrderResolver()
        layers = resolver.resolve(graph)
        assert len(layers) == 3
        assert a.task_id in layers[0]
        assert b.task_id in layers[1]
        assert c.task_id in layers[2]

    def test_diamond_graph_parallel_middle_layer(self, tenant_id, now) -> None:
        """A→B, A→C, B→D, C→D — B and C should be in the same layer."""
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        a = make_operation_task("A")
        b = make_operation_task("B")
        c = make_operation_task("C")
        d = make_operation_task("D")
        for t in [a, b, c, d]:
            graph.add_task(tenant_id, t, now)
        cond = ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE)
        graph.add_dependency(tenant_id, a.task_id, b.task_id, cond, now)
        graph.add_dependency(tenant_id, a.task_id, c.task_id, cond, now)
        graph.add_dependency(tenant_id, b.task_id, d.task_id, cond, now)
        graph.add_dependency(tenant_id, c.task_id, d.task_id, cond, now)

        resolver = ExecutionOrderResolver()
        layers = resolver.resolve(graph)
        assert len(layers) == 3
        assert a.task_id in layers[0]
        parallel_ids = set(layers[1])
        assert b.task_id in parallel_ids
        assert c.task_id in parallel_ids
        assert d.task_id in layers[2]

    def test_single_task_graph(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        t = make_operation_task("Only Task")
        graph.add_task(tenant_id, t, now)
        resolver = ExecutionOrderResolver()
        layers = resolver.resolve(graph)
        assert len(layers) == 1
        assert t.task_id in layers[0]

    def test_empty_graph_returns_empty_layers(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        resolver = ExecutionOrderResolver()
        layers = resolver.resolve(graph)
        assert layers == []

    def test_independent_tasks_same_layer(self, tenant_id, now) -> None:
        """Three tasks with no dependencies should all be in layer 0."""
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        t1 = make_operation_task("T1")
        t2 = make_operation_task("T2")
        t3 = make_operation_task("T3")
        for t in [t1, t2, t3]:
            graph.add_task(tenant_id, t, now)
        resolver = ExecutionOrderResolver()
        layers = resolver.resolve(graph)
        assert len(layers) == 1
        assert {t1.task_id, t2.task_id, t3.task_id} == set(layers[0])

    def test_50_node_graph_correct_layer_count(self, tenant_id, now) -> None:
        """Linear chain of 50 nodes should produce 50 layers."""
        graph = make_task_graph(
            tenant_id=tenant_id, now=now, engagement_window_seconds=999999,
            pop_events=True
        )
        tasks = [make_operation_task(f"Task-{i}", timeout_seconds=100) for i in range(50)]
        for t in tasks:
            graph.add_task(tenant_id, t, now)
        cond = ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE)
        for i in range(len(tasks) - 1):
            graph.add_dependency(tenant_id, tasks[i].task_id, tasks[i + 1].task_id, cond, now)
        resolver = ExecutionOrderResolver()
        layers = resolver.resolve(graph)
        assert len(layers) == 50


class TestGetReadyTasks:
    def test_initial_ready_tasks_are_roots(self, tenant_id, now) -> None:
        """Initially, only tasks with no predecessors are ready."""
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        a = make_operation_task("A")
        b = make_operation_task("B")
        graph.add_task(tenant_id, a, now)
        graph.add_task(tenant_id, b, now)
        cond = ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE)
        graph.add_dependency(tenant_id, a.task_id, b.task_id, cond, now)

        resolver = ExecutionOrderResolver()
        ready = resolver.get_ready_tasks(
            graph,
            completed_task_ids=frozenset(),
            skipped_task_ids=frozenset(),
        )
        assert a.task_id in ready
        assert b.task_id not in ready

    def test_after_completing_root_successor_becomes_ready(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        a = make_operation_task("A")
        b = make_operation_task("B")
        graph.add_task(tenant_id, a, now)
        graph.add_task(tenant_id, b, now)
        cond = ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE)
        graph.add_dependency(tenant_id, a.task_id, b.task_id, cond, now)

        resolver = ExecutionOrderResolver()
        ready = resolver.get_ready_tasks(
            graph,
            completed_task_ids=frozenset({a.task_id}),
            skipped_task_ids=frozenset(),
        )
        assert b.task_id in ready
        assert a.task_id not in ready

    def test_diamond_parallel_completion_unlocks_sink(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        a = make_operation_task("A")
        b = make_operation_task("B")
        c = make_operation_task("C")
        d = make_operation_task("D")
        for t in [a, b, c, d]:
            graph.add_task(tenant_id, t, now)
        cond = ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE)
        graph.add_dependency(tenant_id, a.task_id, b.task_id, cond, now)
        graph.add_dependency(tenant_id, a.task_id, c.task_id, cond, now)
        graph.add_dependency(tenant_id, b.task_id, d.task_id, cond, now)
        graph.add_dependency(tenant_id, c.task_id, d.task_id, cond, now)

        resolver = ExecutionOrderResolver()

        # Complete A — B and C should be ready
        ready = resolver.get_ready_tasks(
            graph,
            completed_task_ids=frozenset({a.task_id}),
            skipped_task_ids=frozenset(),
        )
        assert b.task_id in ready
        assert c.task_id in ready
        assert d.task_id not in ready

        # Complete B but not C — D not yet ready
        ready = resolver.get_ready_tasks(
            graph,
            completed_task_ids=frozenset({a.task_id, b.task_id}),
            skipped_task_ids=frozenset(),
        )
        assert d.task_id not in ready

        # Complete both B and C — D should be ready
        ready = resolver.get_ready_tasks(
            graph,
            completed_task_ids=frozenset({a.task_id, b.task_id, c.task_id}),
            skipped_task_ids=frozenset(),
        )
        assert d.task_id in ready
