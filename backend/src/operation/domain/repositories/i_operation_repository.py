"""IOperationRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from operation.domain.aggregates.operation import Operation
    from operation.domain.value_objects.identifiers import (
        EngagementId,
        OperationId,
        TenantId,
    )


class IOperationRepository(ABC):
    @abstractmethod
    async def save(self, operation: Operation) -> None: ...

    @abstractmethod
    async def find_by_id(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
    ) -> Operation | None: ...

    @abstractmethod
    async def find_by_engagement(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Operation]: ...
