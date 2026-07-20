"""Inventory ACL — resolve TargetRef from asset_id + tenant_id."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from engagement.domain.value_objects.engagement_vos import TargetRef
    from engagement.domain.value_objects.identifiers import TenantId


class IAssetQueryPort(ABC):
    @abstractmethod
    async def resolve_target_ref(
        self,
        asset_id: UUID,
        tenant_id: TenantId,
    ) -> TargetRef | None:
        """Return TargetRef or None if asset cannot be resolved for tenant."""
