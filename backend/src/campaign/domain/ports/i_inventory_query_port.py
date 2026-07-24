"""Anti-Corruption Layer port: inventory query interface (ACL to M22)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from campaign.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from campaign.domain.value_objects.campaign_vos import TargetRef


class IInventoryQueryPort(ABC):
    """ACL interface for querying M22 asset inventory.

    Implementations translate M22 asset records into TargetRef value objects
    without leaking M22 domain concepts into the campaign bounded context.
    """

    @abstractmethod
    async def resolve_targets(
        self,
        rules: list[dict[str, str]],
        tenant_id: TenantId,
    ) -> list[TargetRef]:
        """Return all assets matching the provided filter rules for a tenant."""
