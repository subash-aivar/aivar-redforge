"""Shared fixtures for TaskGraph domain and application tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from taskgraph.domain.aggregates.task_graph import TaskGraph
from taskgraph.domain.entities.task_graph_entities import CampaignTask, TaskDependency
from taskgraph.domain.value_objects.enums import (
    DependencyPredicate,
    TaskCriticality,
    TaskType,
)
from taskgraph.domain.value_objects.identifiers import (
    CampaignTaskId,
    TaskGraphId,
    TaskGroupId,
    TenantId,
)
from taskgraph.domain.value_objects.task_graph_vos import (
    ConditionalBranchConfig,
    TaskOperationTemplate,
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: marks tests requiring PostgreSQL",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("TEST_DATABASE_URL"):
        return
    skip_integration = pytest.mark.skip(
        reason="TEST_DATABASE_URL not set — skipping integration tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


def make_task_graph(
    *,
    tenant_id: TenantId,
    now: datetime,
    engagement_window_seconds: int = 86400,
    pop_events: bool = False,
) -> TaskGraph:
    graph = TaskGraph.create(
        graph_id=TaskGraphId.generate(),
        tenant_id=tenant_id,
        name="APT29 Kill Chain",
        description="Simulates APT29 initial access and lateral movement",
        engagement_window_seconds=engagement_window_seconds,
        now=now,
    )
    if pop_events:
        graph.pop_events()
    return graph


def make_operation_task(
    name: str = "Initial Access",
    criticality: TaskCriticality = TaskCriticality.REQUIRED,
    timeout_seconds: int = 300,
    task_group_id: TaskGroupId | None = None,
) -> CampaignTask:
    return CampaignTask(
        task_id=CampaignTaskId.generate(),
        task_type=TaskType.OPERATION_TASK,
        name=name,
        criticality=criticality,
        timeout_seconds=timeout_seconds,
        operation_template=TaskOperationTemplate(
            technique_id="T1566.001",
            technique_name="Phishing: Spearphishing Attachment",
            parameters={},
            timeout_seconds=timeout_seconds,
        ),
        human_approval_config=None,
        barrier_policy=None,
        rollback_config=None,
        task_group_id=task_group_id,
        rollback_task_ref=None,
    )


def make_dependency(
    predecessor: CampaignTask,
    successor: CampaignTask,
    predicate: DependencyPredicate = DependencyPredicate.EXECUTE_ON_SUCCESS,
) -> TaskDependency:
    return TaskDependency(
        predecessor_id=predecessor.task_id,
        successor_id=successor.task_id,
        condition=ConditionalBranchConfig(predicate=predicate),
    )
