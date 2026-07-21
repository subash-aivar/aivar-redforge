from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance
    from ai_supply_chain.domain.value_objects.identifiers import (
        AISystemAssetId,
        ModelProvenanceId,
        TenantId,
    )


class IModelProvenanceRepository(ABC):
    @abstractmethod
    async def save(self, provenance: ModelProvenance) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, provenance_id: ModelProvenanceId, tenant_id: TenantId
    ) -> ModelProvenance | None: ...

    @abstractmethod
    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> ModelProvenance | None: ...

    @abstractmethod
    async def find_mismatched(self, tenant_id: TenantId) -> list[ModelProvenance]: ...
