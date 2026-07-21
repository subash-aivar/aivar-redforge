"""ITaskGraphRepository — abstract persistence interface for TaskGraph aggregates."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from taskgraph.domain.aggregates.task_graph import TaskGraph
    from taskgraph.domain.value_objects.identifiers import TaskGraphId, TenantId
    from taskgraph.domain.value_objects.task_graph_vos import TaskGraphVersion


class ITaskGraphRepository(ABC):
    @abstractmethod
    async def save(self, graph: TaskGraph) -> None:
        """Persist the TaskGraph aggregate (insert or update with optimistic lock)."""

    @abstractmethod
    async def find_by_id(
        self,
        graph_id: TaskGraphId,
        tenant_id: TenantId,
    ) -> TaskGraph | None:
        """Find a TaskGraph by its ID within a tenant."""

    @abstractmethod
    async def find_signed_version(
        self,
        graph_id: TaskGraphId,
        version: TaskGraphVersion,
        tenant_id: TenantId,
    ) -> TaskGraph | None:
        """Find a specific signed version of a TaskGraph."""

    @abstractmethod
    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[TaskGraph]:
        """Return all Active task graphs for a tenant."""
