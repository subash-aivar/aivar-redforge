"""In-memory fake repositories for taskgraph tests."""

from __future__ import annotations

from taskgraph.domain.aggregates.task_graph import TaskGraph
from taskgraph.domain.repositories.i_task_graph_repository import ITaskGraphRepository
from taskgraph.domain.value_objects.enums import TaskGraphState
from taskgraph.domain.value_objects.identifiers import TaskGraphId, TenantId
from taskgraph.domain.value_objects.task_graph_vos import TaskGraphVersion


class FakeTaskGraphRepository(ITaskGraphRepository):
    def __init__(self) -> None:
        self._store: dict[tuple[str, str], TaskGraph] = {}

    async def save(self, graph: TaskGraph) -> None:
        key = (str(graph.graph_id), str(graph.tenant_id))
        self._store[key] = graph

    async def find_by_id(self, graph_id: TaskGraphId, tenant_id: TenantId) -> TaskGraph | None:
        return self._store.get((str(graph_id), str(tenant_id)))

    async def find_signed_version(
        self,
        graph_id: TaskGraphId,
        version: TaskGraphVersion,
        tenant_id: TenantId,
    ) -> TaskGraph | None:
        for graph in self._store.values():
            if (
                graph.graph_id == graph_id
                and graph.tenant_id == tenant_id
                and str(graph.version) == str(version)
                and graph.state
                in {TaskGraphState.SIGNED, TaskGraphState.ACTIVE, TaskGraphState.DEPRECATED}
            ):
                return graph
        return None

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[TaskGraph]:
        return [
            g
            for g in self._store.values()
            if g.tenant_id == tenant_id and g.state == TaskGraphState.ACTIVE
        ]
