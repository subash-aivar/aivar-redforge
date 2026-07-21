from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.aggregates.ai_compliance_mapping import AIComplianceMapping
    from ai_posture.domain.value_objects.enums import ComplianceFrameworkId
    from ai_posture.domain.value_objects.identifiers import (
        AIComplianceMappingId,
        AISystemAssetId,
        TenantId,
    )


class IAIComplianceMappingRepository(ABC):
    @abstractmethod
    async def save(self, mapping: AIComplianceMapping) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, mapping_id: AIComplianceMappingId, tenant_id: TenantId
    ) -> AIComplianceMapping | None: ...

    @abstractmethod
    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> list[AIComplianceMapping]: ...

    @abstractmethod
    async def find_gaps_by_framework(
        self, framework_id: ComplianceFrameworkId, tenant_id: TenantId
    ) -> list[AIComplianceMapping]: ...

    @abstractmethod
    async def count_gaps_for_asset(self, asset_id: AISystemAssetId, tenant_id: TenantId) -> int: ...
