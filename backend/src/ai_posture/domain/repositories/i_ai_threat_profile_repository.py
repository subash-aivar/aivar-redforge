"""IAIThreatProfileRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.aggregates.ai_threat_profile import AIThreatProfile
    from ai_posture.domain.value_objects.identifiers import (
        AISystemAssetId,
        AIThreatProfileId,
        TenantId,
    )


class IAIThreatProfileRepository(ABC):
    @abstractmethod
    async def save(self, profile: AIThreatProfile) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, profile_id: AIThreatProfileId, tenant_id: TenantId
    ) -> AIThreatProfile | None: ...

    @abstractmethod
    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AIThreatProfile | None: ...

    @abstractmethod
    async def find_stale(
        self, threshold_days: int, tenant_id: TenantId
    ) -> list[AIThreatProfile]: ...
