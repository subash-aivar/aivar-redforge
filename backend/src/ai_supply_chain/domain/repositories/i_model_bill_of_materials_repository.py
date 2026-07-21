from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.aggregates.model_bill_of_materials import (
        ModelBillOfMaterials,
    )
    from ai_supply_chain.domain.value_objects.identifiers import (
        ModelProvenanceId,
        TenantId,
    )
    from ai_supply_chain.domain.value_objects.supply_chain_vos import MBOMComponent


class IModelBillOfMaterialsRepository(ABC):
    @abstractmethod
    async def save(self, mbom: ModelBillOfMaterials) -> None: ...

    @abstractmethod
    async def find_by_provenance(
        self, provenance_id: ModelProvenanceId, tenant_id: TenantId
    ) -> ModelBillOfMaterials | None: ...

    @abstractmethod
    async def find_components_with_known_cve(self, tenant_id: TenantId) -> list[MBOMComponent]: ...
