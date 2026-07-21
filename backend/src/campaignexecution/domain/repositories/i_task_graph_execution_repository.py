"""ITaskGraphExecutionRepository — abstract repository for TaskGraphExecution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaignexecution.domain.aggregates.task_graph_execution import TaskGraphExecution
    from campaignexecution.domain.entities.execution_entities import TaskExecutionRecord
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignInstanceId,
        TaskGraphExecutionId,
        TenantId,
    )


class ITaskGraphExecutionRepository(ABC):
    @abstractmethod
    async def save(self, execution: TaskGraphExecution) -> None:
        """Upsert the execution aggregate with optimistic locking."""

    @abstractmethod
    async def find_by_id(
        self,
        execution_id: TaskGraphExecutionId,
        tenant_id: TenantId,
    ) -> TaskGraphExecution | None:
        """Find execution by ID, scoped to tenant."""

    @abstractmethod
    async def find_by_campaign_instance(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> TaskGraphExecution | None:
        """Find the execution for a specific campaign instance."""

    @abstractmethod
    async def find_pending_dispatch_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[TaskExecutionRecord]:
        """Find all task execution records in ReadyToDispatch state for a tenant."""
