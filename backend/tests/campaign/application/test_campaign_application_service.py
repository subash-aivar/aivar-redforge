"""Campaign application service tests — create, objective, approval, start instance."""

from __future__ import annotations

from types import TracebackType
from uuid import UUID, uuid4

import pytest

from campaign.application.commands.campaign_commands import (
    AddCampaignObjectiveCommand,
    AddTargetSelectionRuleCommand,
    ApproveCampaignCommand,
    CreateCampaignCommand,
    StartCampaignInstanceCommand,
    SubmitCampaignForApprovalCommand,
)
from campaign.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from campaign.application.ports.i_event_publisher import IEventPublisher
from campaign.application.ports.i_unit_of_work import IUnitOfWork
from campaign.application.services.campaign_application_service import (
    CampaignApplicationService,
)
from campaign.domain.events.base import BaseDomainEvent
from campaign.domain.ports.i_engagement_query_port import (
    EngagementStatus,
    IEngagementQueryPort,
)
from campaign.domain.ports.i_inventory_query_port import IInventoryQueryPort
from campaign.domain.repositories.i_campaign_instance_repository import (
    ICampaignInstanceRepository,
)
from campaign.domain.repositories.i_campaign_repository import ICampaignRepository
from campaign.domain.value_objects.campaign_vos import TargetRef
from campaign.domain.value_objects.enums import CampaignState, InstanceState
from campaign.domain.value_objects.identifiers import TenantId
from tests.campaign.fakes.repos import (
    FakeCampaignInstanceRepository,
    FakeCampaignRepository,
)


class FakeUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        campaigns: ICampaignRepository,
        campaign_instances: ICampaignInstanceRepository,
    ) -> None:
        super().__init__()
        self.campaigns = campaigns  # type: ignore[assignment]
        self.campaign_instances = campaign_instances  # type: ignore[assignment]
        self.committed = False
        self.rolled_back = False

    async def commit(self) -> None:
        self._committed = True
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)


class FakeEngagementPort(IEngagementQueryPort):
    def __init__(self, state: str = "Active", kill_switch: str = "Armed") -> None:
        self._state = state
        self._kill_switch = kill_switch

    async def get_engagement_status(
        self, engagement_id: UUID, tenant_id: UUID
    ) -> EngagementStatus | None:
        return EngagementStatus(
            engagement_id=engagement_id,
            state=self._state,
            kill_switch_state=self._kill_switch,
            allowed_target_ids=None,  # None = no scope restriction
        )


class FakeInventoryPort(IInventoryQueryPort):
    def __init__(self, targets: list[TargetRef] | None = None) -> None:
        self._targets = targets or [TargetRef(asset_id=uuid4(), asset_type="Server")]

    async def resolve_targets(
        self, rules: list[dict[str, str]], tenant_id: UUID
    ) -> list[TargetRef]:
        return self._targets


def make_service(
    tenant_id: TenantId,
    engagement_state: str = "Active",
    kill_switch: str = "Armed",
    resolved_targets: list[TargetRef] | None = None,
) -> tuple[CampaignApplicationService, FakeUnitOfWork, FakeEventPublisher]:
    campaign_repo = FakeCampaignRepository()
    instance_repo = FakeCampaignInstanceRepository()
    uow = FakeUnitOfWork(campaigns=campaign_repo, campaign_instances=instance_repo)
    publisher = FakeEventPublisher()
    engagement_port = FakeEngagementPort(state=engagement_state, kill_switch=kill_switch)
    inventory_port = FakeInventoryPort(targets=resolved_targets)

    def uow_factory() -> FakeUnitOfWork:
        return uow

    svc = CampaignApplicationService(
        uow_factory=uow_factory,
        event_publisher=publisher,
        engagement_port=engagement_port,
        inventory_port=inventory_port,
    )
    return svc, uow, publisher


class TestCreateCampaign:
    @pytest.mark.asyncio
    async def test_create_persists_campaign(self, tenant_id, now) -> None:
        svc, uow, _ = make_service(tenant_id)
        cmd = CreateCampaignCommand(
            tenant_id=tenant_id.value,
            name="Kill Chain Test",
            classification="FullKillChain",
            kind="OneShot",
            owner_id="red-team-lead",
            engagement_id=uuid4(),
        )
        dto = await svc.create_campaign(cmd)
        assert dto.name == "Kill Chain Test"
        assert dto.state == "Draft"
        assert uow.committed

    @pytest.mark.asyncio
    async def test_create_empty_name_raises(self, tenant_id, now) -> None:
        svc, _, _ = make_service(tenant_id)
        cmd = CreateCampaignCommand(
            tenant_id=tenant_id.value,
            name="   ",
            classification="FullKillChain",
            kind="OneShot",
            owner_id="red-team-lead",
            engagement_id=uuid4(),
        )
        with pytest.raises(ApplicationValidationError):
            await svc.create_campaign(cmd)

    @pytest.mark.asyncio
    async def test_create_publishes_events(self, tenant_id, now) -> None:
        svc, _, publisher = make_service(tenant_id)
        cmd = CreateCampaignCommand(
            tenant_id=tenant_id.value,
            name="Detection Tuning",
            classification="DetectionTuning",
            kind="Recurring",
            owner_id="red-team-lead",
            engagement_id=uuid4(),
        )
        await svc.create_campaign(cmd)
        assert len(publisher.published) >= 1


class TestAddObjective:
    @pytest.mark.asyncio
    async def test_add_objective_succeeds(self, tenant_id, now) -> None:
        svc, uow, _ = make_service(tenant_id)
        engagement_id = uuid4()
        create_cmd = CreateCampaignCommand(
            tenant_id=tenant_id.value,
            name="Campaign A",
            classification="FullKillChain",
            kind="OneShot",
            owner_id="owner",
            engagement_id=engagement_id,
        )
        dto = await svc.create_campaign(create_cmd)

        add_cmd = AddCampaignObjectiveCommand(
            tenant_id=tenant_id.value,
            campaign_id=dto.campaign_id,
            objective_type="AccessAchieved",
            description="Access database tier",
            condition_type="AttackActionCompleted",
            condition_parameters={},
        )
        await svc.add_objective(add_cmd)
        # verify via repository
        from campaign.domain.value_objects.identifiers import CampaignId

        campaigns = uow.campaigns
        campaign = await campaigns.find_by_id(CampaignId(dto.campaign_id), tenant_id)
        assert campaign is not None
        assert len(campaign.objectives) == 1

    @pytest.mark.asyncio
    async def test_add_objective_missing_campaign_raises(self, tenant_id, now) -> None:
        svc, _, _ = make_service(tenant_id)
        add_cmd = AddCampaignObjectiveCommand(
            tenant_id=tenant_id.value,
            campaign_id=uuid4(),
            objective_type="AccessAchieved",
            description="Does not matter",
            condition_type="AttackActionCompleted",
            condition_parameters={},
        )
        with pytest.raises(ApplicationNotFoundError):
            await svc.add_objective(add_cmd)


class TestApprovalFlow:
    @pytest.mark.asyncio
    async def test_full_approval_workflow(self, tenant_id, now) -> None:
        svc, uow, _ = make_service(tenant_id)
        engagement_id = uuid4()

        create_cmd = CreateCampaignCommand(
            tenant_id=tenant_id.value,
            name="Full Kill Chain",
            classification="FullKillChain",
            kind="OneShot",
            owner_id="owner",
            engagement_id=engagement_id,
        )
        dto = await svc.create_campaign(create_cmd)
        campaign_id = dto.campaign_id

        # Add target rule
        await svc.add_target_selection_rule(
            AddTargetSelectionRuleCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
                attribute="environment",
                operator="eq",
                value="staging",
            )
        )

        # Submit for approval
        await svc.submit_for_approval(
            SubmitCampaignForApprovalCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
            )
        )

        # Approve
        await svc.approve_campaign(
            ApproveCampaignCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
                approver_id="approver-1",
                signature="sig-abc",
            )
        )

        # Verify approved state
        from campaign.domain.value_objects.identifiers import CampaignId

        campaign = await uow.campaigns.find_by_id(CampaignId(campaign_id), tenant_id)
        assert campaign is not None
        assert campaign.state == CampaignState.APPROVED


class TestStartCampaignInstance:
    @pytest.mark.asyncio
    async def test_start_instance_with_valid_engagement(self, tenant_id, now) -> None:
        resolved_targets = [
            TargetRef(asset_id=uuid4(), asset_type="Server"),
            TargetRef(asset_id=uuid4(), asset_type="Database"),
        ]
        engagement_id = uuid4()
        # Need engagement port to return allowed_target_ids
        campaign_repo = FakeCampaignRepository()
        instance_repo = FakeCampaignInstanceRepository()

        class ActiveEngagementPort(IEngagementQueryPort):
            async def get_engagement_status(
                self, eng_id: UUID, tenant_id_: UUID
            ) -> EngagementStatus | None:
                return EngagementStatus(
                    engagement_id=eng_id,
                    state="Active",
                    kill_switch_state="Armed",
                    allowed_target_ids=[t.asset_id for t in resolved_targets],
                )

        class InventoryPort(IInventoryQueryPort):
            async def resolve_targets(
                self, rules: list[dict[str, str]], tid: UUID
            ) -> list[TargetRef]:
                return resolved_targets

        uow = FakeUnitOfWork(campaigns=campaign_repo, campaign_instances=instance_repo)
        publisher = FakeEventPublisher()

        def uow_factory() -> FakeUnitOfWork:
            return uow

        svc = CampaignApplicationService(
            uow_factory=uow_factory,
            event_publisher=publisher,
            engagement_port=ActiveEngagementPort(),
            inventory_port=InventoryPort(),
        )

        # Create and fully approve campaign
        dto = await svc.create_campaign(
            CreateCampaignCommand(
                tenant_id=tenant_id.value,
                name="Kill Chain Campaign",
                classification="FullKillChain",
                kind="OneShot",
                owner_id="owner",
                engagement_id=engagement_id,
            )
        )
        campaign_id = dto.campaign_id
        await svc.add_target_selection_rule(
            AddTargetSelectionRuleCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
                attribute="environment",
                operator="eq",
                value="staging",
            )
        )
        await svc.submit_for_approval(
            SubmitCampaignForApprovalCommand(tenant_id=tenant_id.value, campaign_id=campaign_id)
        )
        await svc.approve_campaign(
            ApproveCampaignCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
                approver_id="approver-1",
                signature="sig-1",
            )
        )

        # Start instance
        instance_dto = await svc.start_campaign_instance(
            StartCampaignInstanceCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
            )
        )
        assert instance_dto.state == InstanceState.RUNNING
        assert instance_dto.resolved_target_count == 2

    @pytest.mark.asyncio
    async def test_start_instance_suspended_engagement_raises(self, tenant_id, now) -> None:
        from campaign.application.exceptions import ApplicationConflictError

        svc, _, _ = make_service(tenant_id, engagement_state="Suspended", kill_switch="Triggered")
        engagement_id = uuid4()
        dto = await svc.create_campaign(
            CreateCampaignCommand(
                tenant_id=tenant_id.value,
                name="Blocked Campaign",
                classification="FullKillChain",
                kind="OneShot",
                owner_id="owner",
                engagement_id=engagement_id,
            )
        )
        campaign_id = dto.campaign_id
        await svc.add_target_selection_rule(
            AddTargetSelectionRuleCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
                attribute="environment",
                operator="eq",
                value="staging",
            )
        )
        await svc.submit_for_approval(
            SubmitCampaignForApprovalCommand(tenant_id=tenant_id.value, campaign_id=campaign_id)
        )
        await svc.approve_campaign(
            ApproveCampaignCommand(
                tenant_id=tenant_id.value,
                campaign_id=campaign_id,
                approver_id="approver-1",
                signature="sig-1",
            )
        )
        with pytest.raises((ApplicationConflictError, Exception)):
            await svc.start_campaign_instance(
                StartCampaignInstanceCommand(
                    tenant_id=tenant_id.value,
                    campaign_id=campaign_id,
                )
            )


class TestCrossTenantIsolation:
    @pytest.mark.asyncio
    async def test_cross_tenant_query_returns_none(self, tenant_id, now) -> None:
        svc, _, __ = make_service(tenant_id)
        from campaign.application.dtos.campaign_dtos import GetCampaignQuery
        from campaign.domain.value_objects.identifiers import TenantId as OtherTenantId

        dto = await svc.create_campaign(
            CreateCampaignCommand(
                tenant_id=tenant_id.value,
                name="Tenant A Campaign",
                classification="FullKillChain",
                kind="OneShot",
                owner_id="owner",
                engagement_id=uuid4(),
            )
        )
        other_tenant = OtherTenantId(uuid4())
        result = await svc.get_campaign(
            GetCampaignQuery(
                tenant_id=other_tenant.value,
                campaign_id=dto.campaign_id,
            )
        )
        assert result is None
