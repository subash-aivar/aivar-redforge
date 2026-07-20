"""IDetectionExceptionRepository — tenant-scoped persistence port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.aggregates.detection_exception import DetectionException
    from detection.domain.value_objects.identifiers import (
        DetectionExceptionId,
        TenantId,
    )


class IDetectionExceptionRepository(ABC):
    @abstractmethod
    async def save(self, exception: DetectionException) -> None: ...

    @abstractmethod
    async def find_by_id(
        self,
        exception_id: DetectionExceptionId,
        tenant_id: TenantId,
    ) -> DetectionException | None: ...

    @abstractmethod
    async def find_active_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionException]: ...

    @abstractmethod
    async def find_pending_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionException]: ...

    @abstractmethod
    async def find_expired_candidates(
        self,
        tenant_id: TenantId,
        as_of: datetime,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionException]:
        """Active exceptions whose valid_until has passed."""

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionException]: ...
