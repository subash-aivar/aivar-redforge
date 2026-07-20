"""IDetectionExecutionRepository — tenant-scoped persistence port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.aggregates.detection_execution import DetectionExecution
    from detection.domain.value_objects.enums import ExecutionState
    from detection.domain.value_objects.identifiers import (
        DetectionExecutionId,
        DetectionRuleId,
        TenantId,
    )
    from detection.domain.value_objects.telemetry import TimeWindow


class IDetectionExecutionRepository(ABC):
    @abstractmethod
    async def save(self, execution: DetectionExecution) -> None: ...

    @abstractmethod
    async def find_by_id(
        self,
        execution_id: DetectionExecutionId,
        tenant_id: TenantId,
    ) -> DetectionExecution | None: ...

    @abstractmethod
    async def find_by_rule(
        self,
        rule_id: DetectionRuleId,
        tenant_id: TenantId,
        window: TimeWindow | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionExecution]: ...

    @abstractmethod
    async def find_failed_by_tenant(
        self,
        tenant_id: TenantId,
        since: datetime,
    ) -> list[DetectionExecution]: ...

    @abstractmethod
    async def find_by_state(
        self,
        state: ExecutionState,
        tenant_id: TenantId,
    ) -> list[DetectionExecution]: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionExecution]: ...
