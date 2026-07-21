"""IInventoryQueryPort — ACL to M22 inventory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from ai_posture.domain.value_objects.identifiers import TenantId
    from ai_posture.domain.value_objects.posture_vos import AssetRef


class IInventoryQueryPort(ABC):
    @abstractmethod
    async def resolve_asset_ref(self, asset_id: UUID, tenant_id: TenantId) -> AssetRef | None:
        """Resolve M22 asset to local AssetRef; None if missing; raise on cross-tenant."""
