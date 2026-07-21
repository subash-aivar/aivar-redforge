"""ICampaignMetricsSnapshotRepository — domain repository interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from evaluation.domain.aggregates.campaign_metrics_snapshot import CampaignMetricsSnapshot
    from evaluation.domain.value_objects.identifiers import TenantId


class ICampaignMetricsSnapshotRepository(ABC):
    @abstractmethod
    async def save(self, snapshot: CampaignMetricsSnapshot) -> None:
        """Persist an immutable metrics snapshot."""

    @abstractmethod
    async def find_by_campaign(
        self,
        campaign_id: str,
        tenant_id: TenantId,
        limit: int = 50,
    ) -> list[CampaignMetricsSnapshot]:
        """Return snapshots for a campaign ordered by run_number descending."""

    @abstractmethod
    async def find_by_tenant_since(
        self,
        tenant_id: TenantId,
        since: datetime,
    ) -> list[CampaignMetricsSnapshot]:
        """Return all tenant snapshots since the given timestamp."""
