"""IAssetRegistrationPort — ACL to create M22 AIAsset stubs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.value_objects.identifiers import TenantId
    from ai_posture.domain.value_objects.posture_vos import AssetRef, DiscoveredServiceFingerprint


class IAssetRegistrationPort(ABC):
    @abstractmethod
    async def register_ai_asset_stub(
        self,
        tenant_id: TenantId,
        fingerprint: DiscoveredServiceFingerprint,
    ) -> AssetRef:
        """Create a stub M22 AIAsset for a newly discovered service."""
