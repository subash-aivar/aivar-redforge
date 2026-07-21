"""ACL degraded adapters for campaign — stub implementations for testing without M29/M22."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from campaign.domain.ports.i_engagement_query_port import (
    EngagementStatus,
    IEngagementQueryPort,
)
from campaign.domain.ports.i_inventory_query_port import IInventoryQueryPort
from campaign.domain.ports.i_scheduler_port import ISchedulerPort
from campaign.domain.value_objects.campaign_vos import RecurrencePolicy, TargetRef


class AlwaysActiveEngagementAdapter(IEngagementQueryPort):
    """Stub engagement adapter that returns a fake Active+Armed status.

    Used for integration testing and local development without a live M29 instance.
    Never use in production.
    """

    async def get_engagement_status(
        self,
        engagement_id: UUID,
        tenant_id: UUID,
    ) -> EngagementStatus:
        return EngagementStatus(
            engagement_id=engagement_id,
            state="Active",
            kill_switch_state="Armed",
            allowed_target_ids=None,  # None = no scope restriction
        )


class StubInventoryQueryAdapter(IInventoryQueryPort):
    """Stub inventory adapter that returns synthetic TargetRef objects.

    Generates deterministic stub targets from the provided rules.
    Used for integration testing and local development without a live M22 instance.
    Never use in production.
    """

    async def resolve_targets(
        self,
        rules: list[dict[str, str]],
        tenant_id: UUID,
    ) -> list[TargetRef]:
        stub_id = UUID("00000000-0000-0000-0000-000000000001")
        return [
            TargetRef(
                asset_id=stub_id,
                asset_type="host",
            )
        ]


class StubSchedulerPort(ISchedulerPort):
    """Stub scheduler port for testing. Records registered/cancelled jobs."""

    def __init__(self) -> None:
        self.registered: list[dict[str, str]] = []
        self.cancelled: list[str] = []

    async def register_schedule(
        self,
        campaign_id: object,
        tenant_id: object,
        policy: RecurrencePolicy,
    ) -> str:
        job_id = f"stub-job-{campaign_id}"
        self.registered.append({"campaign_id": str(campaign_id), "job_id": job_id})
        return job_id

    async def cancel_schedule(
        self,
        campaign_id: object,
        tenant_id: object,
        job_id: str,
    ) -> None:
        self.cancelled.append(job_id)

    async def get_next_fire_time(
        self,
        cron_expression: str,
        after: datetime,
    ) -> datetime:
        from croniter import croniter

        it = croniter(cron_expression, after)
        result: datetime = it.get_next(datetime)
        return result

    async def list_active_schedules(self, tenant_id: object) -> list[dict[str, str]]:
        return [r for r in self.registered if r["job_id"] not in self.cancelled]
