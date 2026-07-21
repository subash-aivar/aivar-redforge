"""ISchedulerPort — outbound port for registering recurring campaign schedules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from campaign.domain.value_objects.campaign_vos import RecurrencePolicy
    from campaign.domain.value_objects.identifiers import CampaignId, TenantId


class ISchedulerPort(ABC):
    """Platform scheduler integration port for recurring campaign scheduling.

    Implementations register cron-based schedules with the platform scheduler
    (e.g., APScheduler, Celery Beat, cloud schedulers). When the schedule fires,
    they must invoke RecurrenceScheduler.handle_schedule_fire().
    """

    @abstractmethod
    async def register_schedule(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId,
        policy: RecurrencePolicy,
    ) -> str:
        """Register a recurring schedule. Returns a scheduler job ID."""

    @abstractmethod
    async def cancel_schedule(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId,
        job_id: str,
    ) -> None:
        """Cancel a previously registered schedule."""

    @abstractmethod
    async def get_next_fire_time(
        self,
        cron_expression: str,
        after: datetime,
    ) -> datetime:
        """Compute the next fire time for a cron expression after the given datetime."""

    @abstractmethod
    async def list_active_schedules(
        self,
        tenant_id: TenantId,
    ) -> list[dict[str, str]]:
        """Return active schedule registrations for a tenant (for recovery after restart)."""
