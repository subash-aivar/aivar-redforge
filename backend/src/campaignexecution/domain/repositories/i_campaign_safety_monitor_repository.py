"""ICampaignSafetyMonitorRepository — abstract repository for CampaignSafetyMonitor."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaignexecution.domain.aggregates.campaign_safety_monitor import CampaignSafetyMonitor
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignInstanceId,
        TenantId,
    )


class ICampaignSafetyMonitorRepository(ABC):
    @abstractmethod
    async def save(self, monitor: CampaignSafetyMonitor) -> None:
        """Upsert the safety monitor with optimistic locking."""

    @abstractmethod
    async def find_by_campaign_instance(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> CampaignSafetyMonitor | None:
        """Find the safety monitor for a specific campaign instance."""
