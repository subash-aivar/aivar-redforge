"""IExecutionPlanVersionRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from operation.domain.aggregates.execution_plan_version import ExecutionPlanVersion
    from operation.domain.value_objects.identifiers import (
        ExecutionPlanVersionId,
        OperationId,
        TenantId,
    )


class IExecutionPlanVersionRepository(ABC):
    @abstractmethod
    async def save(self, plan_version: ExecutionPlanVersion) -> None: ...

    @abstractmethod
    async def find_by_id(
        self,
        plan_version_id: ExecutionPlanVersionId,
        tenant_id: TenantId,
    ) -> ExecutionPlanVersion | None: ...

    @abstractmethod
    async def find_by_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> list[ExecutionPlanVersion]: ...

    @abstractmethod
    async def find_executing_for_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> ExecutionPlanVersion | None: ...

    @abstractmethod
    async def next_version_number(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> int: ...

    @abstractmethod
    async def find_referencing_payload(
        self,
        tenant_id: TenantId,
        payload_id: str,
    ) -> list[ExecutionPlanVersion]:
        """Return plan versions whose snapshot text contains payload_id."""
        ...
