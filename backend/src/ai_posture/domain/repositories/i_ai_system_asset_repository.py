"""IAISystemAssetRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.aggregates.ai_system_asset import AISystemAsset
    from ai_posture.domain.value_objects.enums import AISystemKind, RegistrationStatus
    from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId
    from ai_posture.domain.value_objects.posture_vos import AssetRef


class IAISystemAssetRepository(ABC):
    @abstractmethod
    async def save(self, asset: AISystemAsset) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AISystemAsset | None: ...

    @abstractmethod
    async def find_by_asset_ref(
        self, asset_ref: AssetRef, tenant_id: TenantId
    ) -> AISystemAsset | None: ...

    @abstractmethod
    async def find_by_registration_status(
        self, status: RegistrationStatus, tenant_id: TenantId
    ) -> list[AISystemAsset]: ...

    @abstractmethod
    async def find_by_kind(
        self, kind: AISystemKind, tenant_id: TenantId
    ) -> list[AISystemAsset]: ...

    @abstractmethod
    async def find_without_owner(self, tenant_id: TenantId) -> list[AISystemAsset]: ...

    @abstractmethod
    async def find_all(self, tenant_id: TenantId) -> list[AISystemAsset]: ...
