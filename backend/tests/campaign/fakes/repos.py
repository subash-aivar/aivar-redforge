"""In-memory fake repositories for campaign tests."""

from __future__ import annotations

from uuid import UUID

from campaign.domain.aggregates.campaign import Campaign
from campaign.domain.aggregates.campaign_instance import CampaignInstance
from campaign.domain.repositories.i_campaign_instance_repository import (
    ICampaignInstanceRepository,
)
from campaign.domain.repositories.i_campaign_repository import ICampaignRepository
from campaign.domain.value_objects.enums import CampaignState, InstanceState
from campaign.domain.value_objects.identifiers import (
    CampaignId,
    CampaignInstanceId,
    TenantId,
)


class FakeCampaignRepository(ICampaignRepository):
    def __init__(self) -> None:
        self._store: dict[tuple[str, str], Campaign] = {}

    async def save(self, campaign: Campaign) -> None:
        key = (str(campaign.campaign_id), str(campaign.tenant_id))
        self._store[key] = campaign

    async def find_by_id(
        self, campaign_id: CampaignId, tenant_id: TenantId
    ) -> Campaign | None:
        return self._store.get((str(campaign_id), str(tenant_id)))

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[Campaign]:
        return [
            c
            for c in self._store.values()
            if c.tenant_id == tenant_id
            and c.state not in {CampaignState.ARCHIVED, CampaignState.COMPLETED, CampaignState.FAILED}
        ]

    async def find_by_engagement(
        self, engagement_id: UUID, tenant_id: TenantId
    ) -> list[Campaign]:
        return [
            c
            for c in self._store.values()
            if c.tenant_id == tenant_id
            and c.engagement_ref is not None
            and c.engagement_ref.engagement_id == engagement_id
        ]

    async def find_by_state(
        self, state: CampaignState, tenant_id: TenantId
    ) -> list[Campaign]:
        return [
            c
            for c in self._store.values()
            if c.tenant_id == tenant_id and c.state == state
        ]


class FakeCampaignInstanceRepository(ICampaignInstanceRepository):
    def __init__(self) -> None:
        self._store: dict[str, CampaignInstance] = {}

    async def save(self, instance: CampaignInstance) -> None:
        self._store[str(instance.instance_id)] = instance

    async def find_by_id(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> CampaignInstance | None:
        inst = self._store.get(str(instance_id))
        if inst is None or inst.tenant_id != tenant_id:
            return None
        return inst

    async def find_by_campaign(
        self, campaign_id: CampaignId, tenant_id: TenantId
    ) -> list[CampaignInstance]:
        return [
            i
            for i in self._store.values()
            if i.campaign_id == campaign_id and i.tenant_id == tenant_id
        ]

    async def find_running_by_tenant(
        self, tenant_id: TenantId
    ) -> list[CampaignInstance]:
        return [
            i
            for i in self._store.values()
            if i.tenant_id == tenant_id and i.state == InstanceState.RUNNING
        ]
