"""TaskGraph lifecycle invariants — state machine, signing, immutability."""

from __future__ import annotations

import pytest

from taskgraph.domain.events.task_graph_events import (
    TaskAdded,
    TaskGraphActivated,
    TaskGraphCreated,
    TaskGraphSigned,
    TaskGraphValidated,
)
from taskgraph.domain.exceptions.domain_exceptions import (
    DuplicateTask,
    InvalidStateTransition,
    SignedGraphImmutabilityViolation,
    TaskGraphValidationFailed,
    TenantMismatch,
)
from taskgraph.domain.services.task_graph_validator import TaskGraphValidator
from taskgraph.domain.value_objects.enums import DependencyPredicate, TaskGraphState
from taskgraph.domain.value_objects.identifiers import TenantId
from taskgraph.domain.value_objects.task_graph_vos import ConditionalBranchConfig
from tests.taskgraph.conftest import make_operation_task, make_task_graph


class TestTaskGraphCreation:
    def test_create_emits_created_event(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        events = graph.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], TaskGraphCreated)

    def test_create_starts_in_draft_state(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        assert graph.state == TaskGraphState.DRAFT

    def test_create_starts_at_version_1_0_0(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now)
        assert str(graph.version) == "1.0.0"


class TestAddRemoveTasks:
    def test_add_task_emits_event(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        task = make_operation_task("Initial Access")
        graph.add_task(tenant_id, task, now)
        events = graph.pop_events()
        assert any(isinstance(e, TaskAdded) for e in events)
        assert len(graph.tasks) == 1

    def test_add_duplicate_task_raises(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        task = make_operation_task("Initial Access")
        graph.add_task(tenant_id, task, now)
        with pytest.raises(DuplicateTask):
            graph.add_task(tenant_id, task, now)

    def test_remove_task_succeeds(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        task = make_operation_task("Initial Access")
        graph.add_task(tenant_id, task, now)
        graph.pop_events()
        graph.remove_task(tenant_id, task.task_id, now)
        assert len(graph.tasks) == 0

    def test_wrong_tenant_raises(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        task = make_operation_task("Task A")
        other_tenant = TenantId.generate()
        with pytest.raises(TenantMismatch):
            graph.add_task(other_tenant, task, now)


class TestValidationAndSigning:
    def _build_valid_graph(self, tenant_id, now):
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        t1 = make_operation_task("Recon", timeout_seconds=300)
        t2 = make_operation_task("Initial Access", timeout_seconds=300)
        graph.add_task(tenant_id, t1, now)
        graph.add_task(tenant_id, t2, now)
        graph.add_dependency(
            tenant_id,
            t1.task_id,
            t2.task_id,
            ConditionalBranchConfig(DependencyPredicate.EXECUTE_ON_SUCCESS),
            now,
        )
        graph.pop_events()
        return graph

    def test_validate_transitions_to_validated(self, tenant_id, now) -> None:
        graph = self._build_valid_graph(tenant_id, now)
        validator = TaskGraphValidator()
        graph.validate(tenant_id=tenant_id, validator=validator, now=now)
        assert graph.state == TaskGraphState.VALIDATED
        events = graph.pop_events()
        assert any(isinstance(e, TaskGraphValidated) for e in events)

    def test_sign_transitions_to_signed(self, tenant_id, now) -> None:
        graph = self._build_valid_graph(tenant_id, now)
        validator = TaskGraphValidator()
        graph.validate(tenant_id=tenant_id, validator=validator, now=now)
        graph.pop_events()
        graph.sign(tenant_id=tenant_id, signed_by="operator-1", signature="sig-abc", now=now)
        assert graph.state == TaskGraphState.SIGNED
        assert graph.signed_by == "operator-1"
        events = graph.pop_events()
        assert any(isinstance(e, TaskGraphSigned) for e in events)

    def test_activate_transitions_to_active(self, tenant_id, now) -> None:
        graph = self._build_valid_graph(tenant_id, now)
        validator = TaskGraphValidator()
        graph.validate(tenant_id=tenant_id, validator=validator, now=now)
        graph.sign(tenant_id=tenant_id, signed_by="operator-1", signature="sig-abc", now=now)
        graph.pop_events()
        graph.activate(tenant_id=tenant_id, now=now)
        assert graph.state == TaskGraphState.ACTIVE
        events = graph.pop_events()
        assert any(isinstance(e, TaskGraphActivated) for e in events)

    def test_deprecate_transitions_to_deprecated(self, tenant_id, now) -> None:
        graph = self._build_valid_graph(tenant_id, now)
        validator = TaskGraphValidator()
        graph.validate(tenant_id=tenant_id, validator=validator, now=now)
        graph.sign(tenant_id=tenant_id, signed_by="operator-1", signature="sig-abc", now=now)
        graph.activate(tenant_id=tenant_id, now=now)
        graph.pop_events()
        graph.deprecate(tenant_id=tenant_id, now=now)
        assert graph.state == TaskGraphState.DEPRECATED


class TestSignedGraphImmutability:
    def _signed_graph(self, tenant_id, now):
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        task = make_operation_task("Task A")
        graph.add_task(tenant_id, task, now)
        validator = TaskGraphValidator()
        graph.validate(tenant_id=tenant_id, validator=validator, now=now)
        graph.sign(tenant_id=tenant_id, signed_by="operator-1", signature="sig-abc", now=now)
        graph.pop_events()
        return graph

    def test_add_task_to_signed_graph_raises(self, tenant_id, now) -> None:
        graph = self._signed_graph(tenant_id, now)
        new_task = make_operation_task("New Task")
        with pytest.raises(SignedGraphImmutabilityViolation):
            graph.add_task(tenant_id, new_task, now)

    def test_remove_task_from_signed_graph_raises(self, tenant_id, now) -> None:
        graph = self._signed_graph(tenant_id, now)
        existing_task_id = graph.tasks[0].task_id
        with pytest.raises(SignedGraphImmutabilityViolation):
            graph.remove_task(tenant_id, existing_task_id, now)

    def test_add_dependency_to_signed_graph_raises(self, tenant_id, now) -> None:
        graph = self._signed_graph(tenant_id, now)
        existing_task_id = graph.tasks[0].task_id
        with pytest.raises(SignedGraphImmutabilityViolation):
            graph.add_dependency(
                tenant_id,
                existing_task_id,
                existing_task_id,
                ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
                now,
            )


class TestInvalidTransitions:
    def test_cannot_sign_before_validate(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidStateTransition):
            graph.sign(tenant_id=tenant_id, signed_by="operator-1", signature="sig", now=now)

    def test_cannot_activate_before_sign(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        task = make_operation_task("Task")
        graph.add_task(tenant_id, task, now)
        validator = TaskGraphValidator()
        graph.validate(tenant_id=tenant_id, validator=validator, now=now)
        with pytest.raises(InvalidStateTransition):
            graph.activate(tenant_id=tenant_id, now=now)

    def test_cyclic_graph_fails_validation_and_blocks_signing(self, tenant_id, now) -> None:
        graph = make_task_graph(tenant_id=tenant_id, now=now, pop_events=True)
        t1 = make_operation_task("A")
        t2 = make_operation_task("B")
        graph.add_task(tenant_id, t1, now)
        graph.add_task(tenant_id, t2, now)
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
            t1.task_id,
            ConditionalBranchConfig(DependencyPredicate.ALWAYS_EXECUTE),
            now,
        )
        validator = TaskGraphValidator()
        with pytest.raises(TaskGraphValidationFailed):
            graph.validate(tenant_id=tenant_id, validator=validator, now=now)
