"""ICampaignRepository — domain repository interface for Campaign aggregate."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from campaign.domain.aggregates.campaign import Campaign
    from campaign.domain.value_objects.enums import CampaignState
    from campaign.domain.value_objects.identifiers import CampaignId, TenantId


class ICampaignRepository(ABC):
    @abstractmethod
    async def save(self, campaign: Campaign) -> None:
        """Persist the campaign aggregate (insert or update with optimistic locking)."""

    @abstractmethod
    async def find_by_id(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId,
    ) -> Campaign | None:
        """Return the campaign for the given id and tenant, or None if not found."""

    @abstractmethod
    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[Campaign]:
        """Return all running or paused campaigns for a tenant."""

    @abstractmethod
    async def find_by_engagement(
        self,
        engagement_id: UUID,
        tenant_id: TenantId,
    ) -> list[Campaign]:
        """Return all campaigns linked to the given engagement."""

    @abstractmethod
    async def find_by_state(
        self,
        state: CampaignState,
        tenant_id: TenantId,
    ) -> list[Campaign]:
        """Return all campaigns in the given state for a tenant."""
