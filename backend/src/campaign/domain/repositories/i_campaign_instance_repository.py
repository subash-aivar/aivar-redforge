"""ICampaignInstanceRepository — domain repository interface for CampaignInstance aggregate."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaign.domain.aggregates.campaign_instance import CampaignInstance
    from campaign.domain.value_objects.identifiers import (
        CampaignId,
        CampaignInstanceId,
        TenantId,
    )


class ICampaignInstanceRepository(ABC):
    @abstractmethod
    async def save(self, instance: CampaignInstance) -> None:
        """Persist the instance aggregate (insert or update with optimistic locking)."""

    @abstractmethod
    async def find_by_id(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> CampaignInstance | None:
        """Return the instance for the given id and tenant, or None if not found."""

    @abstractmethod
    async def find_by_campaign(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId,
    ) -> list[CampaignInstance]:
        """Return all instances for the given campaign, ordered by run_number."""

    @abstractmethod
    async def find_running_by_tenant(self, tenant_id: TenantId) -> list[CampaignInstance]:
        """Return all actively running instances for a tenant."""
