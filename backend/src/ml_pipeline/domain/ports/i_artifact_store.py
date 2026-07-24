from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ml_pipeline.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


class IMLModelArtifactStore(ABC):
    @abstractmethod
    async def store_artifact(
        self, tenant_id: TenantId, model_id: UUID, artifact_bytes: bytes
    ) -> str: ...

    @abstractmethod
    async def load_artifact(self, tenant_id: TenantId, model_id: UUID) -> tuple[bytes, str]: ...
