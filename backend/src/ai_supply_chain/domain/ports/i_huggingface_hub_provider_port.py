from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import (
        ArtifactDescriptor,
        DiscoveredAIService,
        MBOMComponent,
    )


@dataclass(frozen=True, slots=True)
class HuggingFaceModelMetadata:
    model_id: str
    artifact: ArtifactDescriptor
    components: tuple[MBOMComponent, ...]


class IHuggingFaceHubProviderPort(ABC):
    @abstractmethod
    async def list_models(self, tenant_id: TenantId) -> list[DiscoveredAIService]: ...

    @abstractmethod
    async def get_model_metadata(
        self, tenant_id: TenantId, model_id: str
    ) -> HuggingFaceModelMetadata: ...
