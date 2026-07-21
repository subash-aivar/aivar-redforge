"""Application tests for scenario distribution and instantiation ACL."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from tests.scenario.fakes.repos import FakeEventPublisher, FakeUnitOfWork

from scenario.application.commands.scenario_commands import (
    CreateScenarioTemplateCommand,
    InstantiateScenarioCommand,
    PublishScenarioTemplateCommand,
    SubscribeScenarioToTenantCommand,
)
from scenario.application.exceptions import ApplicationValidationError
from scenario.application.services.scenario_application_service import (
    ScenarioApplicationService,
)
from scenario.domain.value_objects.enums import ScenarioTemplateState
from scenario.domain.value_objects.identifiers import ScenarioTemplateId, TenantId
from scenario.domain.value_objects.scenario_vos import (
    ScenarioObjectiveBlueprint,
    ScenarioParameterSpec,
)
from scenario.infrastructure.acl.degraded_adapters import (
    StubCampaignDraftPort,
    StubScenarioGraphWriteAdapter,
)


def _make_service(
    uow: FakeUnitOfWork,
    publisher: FakeEventPublisher,
    *,
    draft: StubCampaignDraftPort | None = None,
    graph: StubScenarioGraphWriteAdapter | None = None,
) -> ScenarioApplicationService:
    return ScenarioApplicationService(
        uow_factory=lambda: uow,
        event_publisher=publisher,
        graph_write_port=graph or StubScenarioGraphWriteAdapter(),
        campaign_draft_port=draft or StubCampaignDraftPort(),
    )


async def _create_published(svc: ScenarioApplicationService, tenant: UUID) -> UUID:
    created = await svc.create(
        CreateScenarioTemplateCommand(
            tenant_id=tenant,
            scenario_key="apt29.initial_access",
            version="1.0.0",
            name="APT29",
            covered_techniques=[("T1078", "Valid Accounts")],
            objective_blueprints=[
                ScenarioObjectiveBlueprint(
                    objective_type="AccessAchieved",
                    condition_type="AttackActionCompleted",
                    parameters={"technique_id": "T1078"},
                    is_required=True,
                )
            ],
            task_graph_tasks=[
                {
                    "task_key": "access",
                    "task_type": "AttackAction",
                    "technique_id": "T1078",
                    "depends_on": [],
                    "parameters": {},
                }
            ],
            parameters=[
                ScenarioParameterSpec(
                    name="target",
                    description="t",
                    required=True,
                    default_value="host",
                    parameter_type="string",
                )
            ],
        )
    )
    tid = UUID(created.template_id)
    await svc.publish(PublishScenarioTemplateCommand(tenant_id=tenant, template_id=tid))
    return tid


@pytest.mark.asyncio
async def test_subscribe_creates_tenant_local_copy() -> None:
    uow = FakeUnitOfWork()
    publisher = FakeEventPublisher()
    graph = StubScenarioGraphWriteAdapter()
    svc = _make_service(uow, publisher, graph=graph)
    owner = uuid4()
    subscriber = uuid4()
    template_id = await _create_published(svc, owner)

    local = await svc.subscribe_to_tenant(
        SubscribeScenarioToTenantCommand(
            tenant_id=owner,
            template_id=template_id,
            subscriber_tenant_id=subscriber,
        )
    )
    assert local.tenant_id == str(subscriber)
    assert local.state == ScenarioTemplateState.PUBLISHED.value
    platform = await uow.templates.find_by_id(ScenarioTemplateId(template_id), TenantId(owner))
    assert platform is not None
    assert platform.subscription_scope.contains(str(subscriber))
    assert any(type(e).__name__ == "ScenarioSubscriptionChanged" for e in publisher.events)
    assert any(n["tenant_id"] == str(subscriber) for n in graph.nodes)


@pytest.mark.asyncio
async def test_instantiate_validates_phase1_gates() -> None:
    uow = FakeUnitOfWork()
    publisher = FakeEventPublisher()
    draft = StubCampaignDraftPort()
    graph = StubScenarioGraphWriteAdapter()
    svc = _make_service(uow, publisher, draft=draft, graph=graph)
    tenant = uuid4()
    tid = await _create_published(svc, tenant)
    result = await svc.instantiate(
        InstantiateScenarioCommand(
            tenant_id=tenant,
            template_id=tid,
            parameter_map={},
            engagement_id=uuid4(),
            owner_id="owner-1",
            create_campaign_draft=True,
        )
    )
    assert result.campaign_id is not None
    assert draft.created_campaigns
    assert graph.based_on_scenario_edges
    assert result.metadata["auto_approved"] == "false"


@pytest.mark.asyncio
async def test_instantiate_rejects_invalid_draft() -> None:
    uow = FakeUnitOfWork()
    publisher = FakeEventPublisher()

    class BadDraftPort(StubCampaignDraftPort):
        async def validate_draft_spec(self, *, tenant_id, draft_spec):  # type: ignore[no-untyped-def]
            return ["name is required"]

    svc = _make_service(uow, publisher, draft=BadDraftPort())
    tenant = uuid4()
    tid = await _create_published(svc, tenant)
    with pytest.raises(ApplicationValidationError):
        await svc.instantiate(InstantiateScenarioCommand(tenant_id=tenant, template_id=tid))
