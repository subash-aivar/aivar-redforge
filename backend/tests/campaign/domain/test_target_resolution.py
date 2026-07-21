"""Target resolution and campaign authorization service tests."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from campaign.domain.exceptions.domain_exceptions import (
    EngagementNotActive,
    TargetResolutionFailed,
)
from campaign.domain.ports.i_engagement_query_port import (
    EngagementStatus,
    IEngagementQueryPort,
)
from campaign.domain.ports.i_inventory_query_port import IInventoryQueryPort
from campaign.domain.services.campaign_authorization_service import (
    CampaignAuthorizationService,
)
from campaign.domain.services.target_resolution_service import TargetResolutionService
from campaign.domain.value_objects.campaign_vos import TargetRef, TargetSelectionRule
from tests.campaign.conftest import make_campaign


class StubEngagementPort(IEngagementQueryPort):
    def __init__(self, status: EngagementStatus | None) -> None:
        self._status = status

    async def get_engagement_status(
        self, engagement_id: UUID, tenant_id: UUID
    ) -> EngagementStatus | None:
        return self._status


class StubInventoryPort(IInventoryQueryPort):
    def __init__(self, targets: list[TargetRef]) -> None:
        self._targets = targets

    async def resolve_targets(
        self, rules: list[dict[str, str]], tenant_id: UUID
    ) -> list[TargetRef]:
        return self._targets


class TestTargetResolutionService:
    @pytest.mark.asyncio
    async def test_resolution_produces_selected_target_set(self, tenant_id, now) -> None:
        targets = [
            TargetRef(asset_id=uuid4(), asset_type="Server"),
            TargetRef(asset_id=uuid4(), asset_type="Database"),
        ]
        eng_id = uuid4()
        status = EngagementStatus(
            engagement_id=eng_id,
            state="Active",
            kill_switch_state="Armed",
            allowed_target_ids=[t.asset_id for t in targets],
        )
        inventory_port = StubInventoryPort(targets)
        engagement_port = StubEngagementPort(status)

        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        rules = [TargetSelectionRule(attribute="environment", operator="eq", value="prod")]
        service = TargetResolutionService()
        result = await service.resolve(
            criteria=rules,
            engagement_ref=campaign.engagement_ref,  # type: ignore[arg-type]
            tenant_id=tenant_id,
            inventory_port=inventory_port,
            engagement_port=engagement_port,
        )
        assert result.count == 2

    @pytest.mark.asyncio
    async def test_no_targets_raises(self, tenant_id, now) -> None:
        eng_id = uuid4()
        status = EngagementStatus(
            engagement_id=eng_id,
            state="Active",
            kill_switch_state="Armed",
            allowed_target_ids=[],
        )
        inventory_port = StubInventoryPort([])
        engagement_port = StubEngagementPort(status)

        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        rules = [TargetSelectionRule(attribute="environment", operator="eq", value="prod")]
        service = TargetResolutionService()
        with pytest.raises(TargetResolutionFailed):
            await service.resolve(
                criteria=rules,
                engagement_ref=campaign.engagement_ref,  # type: ignore[arg-type]
                tenant_id=tenant_id,
                inventory_port=inventory_port,
                engagement_port=engagement_port,
            )

    @pytest.mark.asyncio
    async def test_targets_out_of_scope_filtered(self, tenant_id, now) -> None:
        allowed_target = TargetRef(asset_id=uuid4(), asset_type="Server")
        out_of_scope_target = TargetRef(asset_id=uuid4(), asset_type="Database")
        eng_id = uuid4()
        status = EngagementStatus(
            engagement_id=eng_id,
            state="Active",
            kill_switch_state="Armed",
            allowed_target_ids=[allowed_target.asset_id],
        )
        inventory_port = StubInventoryPort([allowed_target, out_of_scope_target])
        engagement_port = StubEngagementPort(status)

        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        rules = [TargetSelectionRule(attribute="environment", operator="eq", value="prod")]
        service = TargetResolutionService()
        result = await service.resolve(
            criteria=rules,
            engagement_ref=campaign.engagement_ref,  # type: ignore[arg-type]
            tenant_id=tenant_id,
            inventory_port=inventory_port,
            engagement_port=engagement_port,
        )
        assert result.count == 1
        assert result.targets[0].asset_id == allowed_target.asset_id

    @pytest.mark.asyncio
    async def test_all_targets_out_of_scope_raises(self, tenant_id, now) -> None:
        target = TargetRef(asset_id=uuid4(), asset_type="Server")
        eng_id = uuid4()
        # No allowed target IDs
        status = EngagementStatus(
            engagement_id=eng_id,
            state="Active",
            kill_switch_state="Armed",
            allowed_target_ids=[],
        )
        inventory_port = StubInventoryPort([target])
        engagement_port = StubEngagementPort(status)

        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        rules = [TargetSelectionRule(attribute="environment", operator="eq", value="prod")]
        service = TargetResolutionService()
        with pytest.raises(TargetResolutionFailed):
            await service.resolve(
                criteria=rules,
                engagement_ref=campaign.engagement_ref,  # type: ignore[arg-type]
                tenant_id=tenant_id,
                inventory_port=inventory_port,
                engagement_port=engagement_port,
            )


class TestCampaignAuthorizationService:
    @pytest.mark.asyncio
    async def test_active_armed_engagement_authorizes(self, tenant_id, now) -> None:
        eng_id = uuid4()
        status = EngagementStatus(
            engagement_id=eng_id,
            state="Active",
            kill_switch_state="Armed",
            allowed_target_ids=[],
        )
        engagement_port = StubEngagementPort(status)
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        service = CampaignAuthorizationService()
        # Should not raise
        await service.authorize(
            campaign=campaign,
            tenant_id=tenant_id,
            engagement_port=engagement_port,
        )

    @pytest.mark.asyncio
    async def test_suspended_engagement_raises(self, tenant_id, now) -> None:
        eng_id = uuid4()
        status = EngagementStatus(
            engagement_id=eng_id,
            state="Suspended",
            kill_switch_state="Triggered",
            allowed_target_ids=[],
        )
        engagement_port = StubEngagementPort(status)
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        service = CampaignAuthorizationService()
        with pytest.raises(EngagementNotActive):
            await service.authorize(
                campaign=campaign,
                tenant_id=tenant_id,
                engagement_port=engagement_port,
            )

    @pytest.mark.asyncio
    async def test_engagement_not_found_raises(self, tenant_id, now) -> None:
        engagement_port = StubEngagementPort(None)
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        service = CampaignAuthorizationService()
        with pytest.raises(EngagementNotActive):
            await service.authorize(
                campaign=campaign,
                tenant_id=tenant_id,
                engagement_port=engagement_port,
            )

    @pytest.mark.asyncio
    async def test_triggered_kill_switch_raises(self, tenant_id, now) -> None:
        eng_id = uuid4()
        status = EngagementStatus(
            engagement_id=eng_id,
            state="Active",
            kill_switch_state="Triggered",
            allowed_target_ids=[],
        )
        engagement_port = StubEngagementPort(status)
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        service = CampaignAuthorizationService()
        with pytest.raises(EngagementNotActive):
            await service.authorize(
                campaign=campaign,
                tenant_id=tenant_id,
                engagement_port=engagement_port,
            )
