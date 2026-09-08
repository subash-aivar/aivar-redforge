"""In-memory fakes for campaign_intel application-layer tests. No ORM,
no real I/O — pure Python collections."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from campaign_intel.application.ports.i_campaign_repository import ICampaignRepository
from campaign_intel.application.ports.i_event_publisher import IEventPublisher
from campaign_intel.application.ports.i_unit_of_work import IUnitOfWork

if TYPE_CHECKING:
    from campaign_intel.domain.aggregates.campaign import Campaign
    from campaign_intel.domain.events.base import BaseDomainEvent
    from campaign_intel.domain.value_objects.enums import (
        CampaignLifecycleStatus,
        CampaignMotivation,
        CampaignStatus,
        CampaignTargetSector,
    )
    from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId


def _tenant_key(tenant_id: TenantId | None) -> str:
    return "" if tenant_id is None else str(tenant_id)


class InMemoryCampaignRepository(ICampaignRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, Campaign] = {}

    async def save(self, campaign: Campaign) -> None:
        self._by_id[str(campaign.campaign_id)] = campaign

    async def get(self, tenant_id: TenantId | None, campaign_id: CampaignId) -> Campaign | None:
        campaign = self._by_id.get(str(campaign_id))
        if campaign is None or _tenant_key(campaign.tenant_id) != _tenant_key(tenant_id):
            return None
        return campaign

    async def get_any(self, campaign_id: CampaignId) -> Campaign | None:
        return self._by_id.get(str(campaign_id))

    async def get_by_canonical_name(
        self, tenant_id: TenantId | None, canonical_name: str
    ) -> Campaign | None:
        for campaign in self._by_id.values():
            if (
                _tenant_key(campaign.tenant_id) == _tenant_key(tenant_id)
                and campaign.canonical_name == canonical_name
            ):
                return campaign
        return None

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: CampaignLifecycleStatus | None = None,
        status: CampaignStatus | None = None,
        motivation: CampaignMotivation | None = None,
        target_sector: CampaignTargetSector | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Campaign]:
        results = [
            c for c in self._by_id.values() if _tenant_key(c.tenant_id) == _tenant_key(tenant_id)
        ]
        if lifecycle_status is not None:
            results = [c for c in results if c.lifecycle_status is lifecycle_status]
        if status is not None:
            results = [c for c in results if c.status is status]
        if motivation is not None:
            results = [c for c in results if c.motivation is motivation]
        if target_sector is not None:
            results = [c for c in results if target_sector in c.target_sectors]
        results = sorted(results, key=lambda c: c.created_at, reverse=True)
        return results[offset : offset + limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self, repo: InMemoryCampaignRepository, *, fail_commit: bool = False) -> None:
        self.campaigns = repo
        self._fail_commit = fail_commit
        self.committed = False
        self.rolled_back = False

    async def commit(self) -> None:
        if self._fail_commit:
            raise RuntimeError("simulated commit failure")
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if exc_type is not None:
            await self.rollback()


class RecordingEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published_batches: list[list[BaseDomainEvent]] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published_batches.append(list(events))

    @property
    def all_published(self) -> list[BaseDomainEvent]:
        return [event for batch in self.published_batches for event in batch]
