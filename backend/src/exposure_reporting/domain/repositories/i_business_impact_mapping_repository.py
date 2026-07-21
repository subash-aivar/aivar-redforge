"""IBusinessImpactMappingRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from exposure_reporting.domain.aggregates.business_impact_mapping import (
        BusinessImpactMapping,
    )
    from exposure_reporting.domain.value_objects.identifiers import (
        BusinessImpactMappingId,
        TenantId,
    )


class IBusinessImpactMappingRepository(ABC):
    @abstractmethod
    async def get(
        self, tenant_id: TenantId, mapping_id: BusinessImpactMappingId
    ) -> BusinessImpactMapping | None: ...

    @abstractmethod
    async def find_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID
    ) -> BusinessImpactMapping | None: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, mapping: BusinessImpactMapping) -> None: ...

    @abstractmethod
    async def list_by_tenant(self, tenant_id: TenantId) -> list[BusinessImpactMapping]: ...
