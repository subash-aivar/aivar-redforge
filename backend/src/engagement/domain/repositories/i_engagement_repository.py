"""IEngagementRepository port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engagement.domain.aggregates.engagement import Engagement
    from engagement.domain.value_objects.enums import EngagementState
    from engagement.domain.value_objects.identifiers import EngagementId, TenantId


class IEngagementRepository(ABC):
    @abstractmethod
    async def save(self, engagement: Engagement) -> None:
        """Persist engagement with optimistic locking on row_version."""

    @abstractmethod
    async def find_by_id(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> Engagement | None:
        """Tenant-scoped lookup."""

    @abstractmethod
    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[Engagement]:
        """Return Active engagements for tenant."""

    @abstractmethod
    async def find_by_state(
        self,
        state: EngagementState,
        tenant_id: TenantId,
    ) -> list[Engagement]:
        """Return engagements in the given state for tenant."""
