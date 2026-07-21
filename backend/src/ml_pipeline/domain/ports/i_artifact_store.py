from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


class IMLModelArtifactStore(ABC):
    @abstractmethod
    async def store_artifact(
        self, tenant_id: UUID, model_id: UUID, artifact_bytes: bytes
    ) -> str: ...

    @abstractmethod
    async def load_artifact(self, tenant_id: UUID, model_id: UUID) -> tuple[bytes, str]: ...
