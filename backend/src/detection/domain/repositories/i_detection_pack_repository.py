"""IDetectionPackRepository — tenant-scoped persistence port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.domain.aggregates.detection_pack import DetectionPack
    from detection.domain.value_objects.identifiers import DetectionPackId, TenantId
    from detection.domain.value_objects.pack import PackKey


class IDetectionPackRepository(ABC):
    @abstractmethod
    async def save(self, pack: DetectionPack) -> None: ...

    @abstractmethod
    async def find_by_id(
        self,
        pack_id: DetectionPackId,
        tenant_id: TenantId,
    ) -> DetectionPack | None: ...

    @abstractmethod
    async def find_by_pack_key(
        self,
        pack_key: PackKey,
        tenant_id: TenantId,
    ) -> DetectionPack | None: ...

    @abstractmethod
    async def find_active_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionPack]: ...

    @abstractmethod
    async def find_by_compliance_framework(
        self,
        framework_ref: str,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionPack]: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionPack]: ...
