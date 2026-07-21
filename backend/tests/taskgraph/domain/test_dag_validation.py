"""DAG validation tests — cycle detection, validator, barrier, human approval."""

from __future__ import annotations

from taskgraph.domain.entities.task_graph_entities import CampaignTask, TaskDependency
from taskgraph.domain.services.task_graph_validator import TaskGraphValidator
from taskgraph.domain.value_objects.enums import (
    DependencyPredicate,
    TaskCriticality,
    TaskType,
)
from taskgraph.domain.value_objects.identifiers import (
    CampaignTaskId,
    TaskGroupId,
)
from taskgraph.domain.value_objects.task_graph_vos import (
    BarrierPolicy,
    ConditionalBranchConfig,
    HumanApprovalTaskConfig,
)
from tests.taskgraph.conftest import (
    make_operation_task,
    make_task_graph,
)


class TestCycleDetection:
    def test_acyclic_graph_no_errors(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        t1 = make_operation_task("Recon")
        t2 = make_operation_task("Initial Access")
        t3 = make_operation_task("Lateral Movement")
        graph.add_task(tenant_id, t1, now)
        graph.add_task(tenant_id, t2, now)
        graph.add_task(tenant_id, t3, now)
        graph.add_dependency(
            tenant_id,
            t1.task_id,
            t2.task_id,
            ConditionalBranchConfig(DependencyPredicate.EXECUTE_ON_SUCCESS),
            now,
        )
        graph.add_dependency(
            tenant_id,
            t2.task_id,
            t3.task_id,
            ConditionalBranchConfig(DependencyPredicate.EXECUTE_ON_SUCCESS),
            now,
        )
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert errors == []

    def test_cycle_detected_reports_error(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        t1 = make_operation_task("A")
        t2 = make_operation_task("B")
        t3 = make_operation_task("C")
        graph.add_task(tenant_id, t1, now)
        graph.add_task(tenant_id, t2, now)
        graph.add_task(tenant_id, t3, now)
        # A → B → C → A (cycle)
        graph.add_dependency(
            tenant_id,
            t1.task_id,
            t2.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        graph.add_dependency(
            tenant_id,
            t2.task_id,
            t3.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        graph.add_dependency(
            tenant_id,
            t3.task_id,
            t1.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert any("Cycle" in e for e in errors)

    def test_diamond_graph_valid(self, tenant_id, now) -> None:
        """A→B, A→C, B→D, C→D is a valid diamond DAG."""
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        a = make_operation_task("A")
        b = make_operation_task("B")
        c = make_operation_task("C")
        d = make_operation_task("D")
        for t in [a, b, c, d]:
            graph.add_task(tenant_id, t, now)
        graph.add_dependency(
            tenant_id,
            a.task_id,
            b.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        graph.add_dependency(
            tenant_id,
            a.task_id,
            c.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        graph.add_dependency(
            tenant_id,
            b.task_id,
            d.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        graph.add_dependency(
            tenant_id,
            c.task_id,
            d.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert errors == []


class TestHumanApprovalValidation:
    def test_human_approval_without_config_fails_validation(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        # HumanApprovalTask without config
        gate_task = CampaignTask(
            task_id=CampaignTaskId.generate(),
            task_type=TaskType.HUMAN_APPROVAL_TASK,
            name="Human Gate",
            criticality=TaskCriticality.REQUIRED,
            timeout_seconds=3600,
            operation_template=None,
            human_approval_config=None,  # missing config
            barrier_policy=None,
            rollback_config=None,
            task_group_id=None,
            rollback_task_ref=None,
        )
        graph.add_task(tenant_id, gate_task, now)
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert any("HumanApprovalTask" in e for e in errors)

    def test_human_approval_with_zero_timeout_fails(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        gate_task = CampaignTask(
            task_id=CampaignTaskId.generate(),
            task_type=TaskType.HUMAN_APPROVAL_TASK,
            name="Human Gate",
            criticality=TaskCriticality.REQUIRED,
            timeout_seconds=3600,
            operation_template=None,
            human_approval_config=HumanApprovalTaskConfig(
                gate_timeout_seconds=0,  # invalid
                required_approver_role="campaign:approver",
                default_on_timeout="abort",
                timeout_justification=None,
            ),
            barrier_policy=None,
            rollback_config=None,
            task_group_id=None,
            rollback_task_ref=None,
        )
        graph.add_task(tenant_id, gate_task, now)
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert any("timeout" in e.lower() for e in errors)

    def test_human_approval_with_valid_config_passes(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        gate_task = CampaignTask(
            task_id=CampaignTaskId.generate(),
            task_type=TaskType.HUMAN_APPROVAL_TASK,
            name="Human Gate",
            criticality=TaskCriticality.REQUIRED,
            timeout_seconds=3600,
            operation_template=None,
            human_approval_config=HumanApprovalTaskConfig(
                gate_timeout_seconds=3600,
                required_approver_role="campaign:approver",
                default_on_timeout="abort",
                timeout_justification=None,
            ),
            barrier_policy=None,
            rollback_config=None,
            task_group_id=None,
            rollback_task_ref=None,
        )
        graph.add_task(tenant_id, gate_task, now)
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert errors == []


class TestBarrierTaskValidation:
    def test_barrier_without_policy_fails(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        barrier = CampaignTask(
            task_id=CampaignTaskId.generate(),
            task_type=TaskType.BARRIER_TASK,
            name="Barrier",
            criticality=TaskCriticality.REQUIRED,
            timeout_seconds=60,
            operation_template=None,
            human_approval_config=None,
            barrier_policy=None,  # missing
            rollback_config=None,
            task_group_id=None,
            rollback_task_ref=None,
        )
        graph.add_task(tenant_id, barrier, now)
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert any("BarrierTask" in e for e in errors)

    def test_barrier_references_nonexistent_group_fails(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        barrier = CampaignTask(
            task_id=CampaignTaskId.generate(),
            task_type=TaskType.BARRIER_TASK,
            name="Barrier",
            criticality=TaskCriticality.REQUIRED,
            timeout_seconds=60,
            operation_template=None,
            human_approval_config=None,
            barrier_policy=BarrierPolicy(task_group_id="group-xyz"),  # nonexistent
            rollback_config=None,
            task_group_id=None,
            rollback_task_ref=None,
        )
        graph.add_task(tenant_id, barrier, now)
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert any("group-xyz" in e for e in errors)

    def test_barrier_with_valid_group_passes(self, tenant_id, now) -> None:
        """Barrier referencing existing group_id passes validation."""
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        group_id = TaskGroupId("parallel-group-1")
        t1 = make_operation_task("T1", task_group_id=group_id)
        t2 = make_operation_task("T2", task_group_id=group_id)
        barrier = CampaignTask(
            task_id=CampaignTaskId.generate(),
            task_type=TaskType.BARRIER_TASK,
            name="Barrier",
            criticality=TaskCriticality.REQUIRED,
            timeout_seconds=60,
            operation_template=None,
            human_approval_config=None,
            barrier_policy=BarrierPolicy(task_group_id="parallel-group-1"),
            rollback_config=None,
            task_group_id=None,
            rollback_task_ref=None,
        )
        for t in [t1, t2, barrier]:
            graph.add_task(tenant_id, t, now)
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert errors == []

    def test_dependency_ref_to_unknown_task_fails(self, tenant_id, now) -> None:
        """Dependency referencing a task not in the graph fails."""
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        t1 = make_operation_task("T1")
        t2 = make_operation_task("T2")
        graph.add_task(tenant_id, t1, now)
        # t2 not added — dependency references unknown task
        # Create dependency manually against unknown task
        graph.dependencies.append(
            TaskDependency(
                predecessor_id=t1.task_id,
                successor_id=t2.task_id,
                condition=ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            )
        )
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        assert any("unknown" in e.lower() for e in errors)


class TestLargeGraph:
    def test_50_node_linear_graph_no_cycle(self, tenant_id, now) -> None:
        """Linear chain of 50 nodes should pass cycle detection."""
        graph = make_task_graph(tenant_id=tenant_id, now=now, engagement_window_seconds=999999)
        tasks = [make_operation_task(f"Task-{i}", timeout_seconds=100) for i in range(50)]
        for task in tasks:
            graph.add_task(tenant_id, task, now)
        for i in range(len(tasks) - 1):
            graph.add_dependency(
                tenant_id,
                tasks[i].task_id,
                tasks[i + 1].task_id,
                ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
                now,
            )
        validator = TaskGraphValidator()
        errors = validator.validate(graph)
        cycle_errors = [e for e in errors if "Cycle" in e]
        assert cycle_errors == []
