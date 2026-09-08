"""ICampaignRepository — implementation-independent (no ORM/DB types).
`tenant_id=None` addresses the global scope; a real `TenantId` addresses
that tenant's own scope only. A concrete adapter must never return a
record whose `tenant_id` does not exactly match the requested scope,
mirroring `IMalwareRepository`'s exact not-found-semantics
discipline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaign_intel.domain.aggregates.campaign import Campaign
    from campaign_intel.domain.value_objects.enums import (
        CampaignLifecycleStatus,
        CampaignMotivation,
        CampaignStatus,
        CampaignTargetSector,
    )
    from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId


class ICampaignRepository(ABC):
    @abstractmethod
    async def save(self, campaign: Campaign) -> None: ...

    @abstractmethod
    async def get(self, tenant_id: TenantId | None, campaign_id: CampaignId) -> Campaign | None: ...

    @abstractmethod
    async def get_any(self, campaign_id: CampaignId) -> Campaign | None:
        """Unscoped lookup by ID only — used exclusively to resolve a
        Campaign's ownership scope (its `tenant_id`) for the API layer's
        ownership-based authorization decision. The caller must
        authorize before using anything from the returned aggregate
        beyond `.tenant_id`."""
        ...

    @abstractmethod
    async def get_by_canonical_name(
        self, tenant_id: TenantId | None, canonical_name: str
    ) -> Campaign | None: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: CampaignLifecycleStatus | None = None,
        status: CampaignStatus | None = None,
        motivation: CampaignMotivation | None = None,
        target_sector: CampaignTargetSector | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Campaign]: ...
