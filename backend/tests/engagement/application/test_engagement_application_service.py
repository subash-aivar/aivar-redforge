"""EngagementApplicationService tests with in-memory fake UoW."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from tests.engagement.fakes.repos import (
    FakeAssetQueryPort,
    FakeDigitalSignaturePort,
    FakeEngagementUnitOfWork,
    FakeEventPublisher,
    InMemoryEngagementRepository,
    InMemoryTargetAuthorizationRepository,
)

from engagement.application.commands.engagement_commands import (
    ActivateEngagementCommand,
    CreateEngagementCommand,
    DefineTargetScopeCommand,
    GrantEngagementApprovalCommand,
    SetEngagementWindowCommand,
    SetRulesOfEngagementCommand,
    SignRulesOfEngagementCommand,
    SubmitEngagementForApprovalCommand,
)
from engagement.application.exceptions import ApplicationNotFoundError
from engagement.application.queries.engagement_queries import GetEngagementQuery
from engagement.application.services.engagement_application_service import (
    EngagementApplicationService,
)
from engagement.domain.value_objects.enums import EngagementState
from engagement.domain.value_objects.identifiers import TenantId


@pytest.fixture
def repos() -> tuple[InMemoryEngagementRepository, InMemoryTargetAuthorizationRepository]:
    return InMemoryEngagementRepository(), InMemoryTargetAuthorizationRepository()


@pytest.fixture
def publisher() -> FakeEventPublisher:
    return FakeEventPublisher()


@pytest.fixture
def service(
    repos: tuple[InMemoryEngagementRepository, InMemoryTargetAuthorizationRepository],
    publisher: FakeEventPublisher,
) -> EngagementApplicationService:
    eng_repo, auth_repo = repos

    def uow_factory() -> FakeEngagementUnitOfWork:
        return FakeEngagementUnitOfWork(eng_repo, auth_repo)

    return EngagementApplicationService(
        uow_factory=uow_factory,
        event_publisher=publisher,
        asset_query=FakeAssetQueryPort(),
        signature_port=FakeDigitalSignaturePort(),
    )


@pytest.mark.asyncio
async def test_create_and_get_engagement(service: EngagementApplicationService) -> None:
    tenant = uuid4()
    dto = await service.create_engagement(
        CreateEngagementCommand(
            tenant_id=tenant,
            name="App Test Engagement",
            classification="FullSimulation",
            owner_id="owner-1",
            required_approver_count=1,
        )
    )
    assert dto.state == EngagementState.DRAFT.value
    assert dto.name == "App Test Engagement"

    loaded = await service.get_engagement(
        GetEngagementQuery(tenant_id=tenant, engagement_id=dto.engagement_id)
    )
    assert loaded.engagement_id == dto.engagement_id


@pytest.mark.asyncio
async def test_cross_tenant_query_returns_not_found(
    service: EngagementApplicationService,
) -> None:
    tenant = uuid4()
    other = uuid4()
    dto = await service.create_engagement(
        CreateEngagementCommand(
            tenant_id=tenant,
            name="Tenant A",
            classification="Internal",
            owner_id="owner-1",
        )
    )
    with pytest.raises(ApplicationNotFoundError):
        await service.get_engagement(
            GetEngagementQuery(tenant_id=other, engagement_id=dto.engagement_id)
        )


@pytest.mark.asyncio
async def test_activation_flow_via_application_service(
    service: EngagementApplicationService,
) -> None:
    tenant = uuid4()
    now = datetime.now(UTC)
    dto = await service.create_engagement(
        CreateEngagementCommand(
            tenant_id=tenant,
            name="Activate Me",
            classification="FullSimulation",
            owner_id="owner-1",
            required_approver_count=1,
        )
    )
    eid = dto.engagement_id
    asset = uuid4()

    await service.define_target_scope(
        DefineTargetScopeCommand(tenant_id=tenant, engagement_id=eid, asset_ids=[asset])
    )
    await service.set_rules_of_engagement(
        SetRulesOfEngagementCommand(
            tenant_id=tenant,
            engagement_id=eid,
            allowed_techniques=["T1059"],
        )
    )
    await service.sign_rules_of_engagement(
        SignRulesOfEngagementCommand(
            tenant_id=tenant,
            engagement_id=eid,
            owner_id="owner-1",
            signature="roe-sig",
        )
    )
    await service.set_window(
        SetEngagementWindowCommand(
            tenant_id=tenant,
            engagement_id=eid,
            authorized_start=now - timedelta(hours=1),
            authorized_end=now + timedelta(days=7),
        )
    )
    await service.submit_for_approval(
        SubmitEngagementForApprovalCommand(tenant_id=tenant, engagement_id=eid)
    )
    approved = await service.grant_approval(
        GrantEngagementApprovalCommand(
            tenant_id=tenant,
            engagement_id=eid,
            approver_id="approver-1",
            signature="ok",
        )
    )
    assert approved.state == EngagementState.APPROVED.value
    assert approved.scope_hash is not None

    active = await service.activate(
        ActivateEngagementCommand(tenant_id=tenant, engagement_id=eid)
    )
    assert active.state == EngagementState.ACTIVE.value
    assert active.kill_switch_state == "Armed"


@pytest.mark.asyncio
async def test_in_memory_repo_cross_tenant_isolation(
    repos: tuple[InMemoryEngagementRepository, InMemoryTargetAuthorizationRepository],
) -> None:
    from tests.engagement.conftest import make_engagement

    eng_repo, _ = repos
    now = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    tenant_a = TenantId(uuid4())
    tenant_b = TenantId(uuid4())
    eng = make_engagement(tenant_id=tenant_a, now=now, pop_events=True)
    await eng_repo.save(eng)

    assert await eng_repo.find_by_id(eng.engagement_id, tenant_a) is not None
    assert await eng_repo.find_by_id(eng.engagement_id, tenant_b) is None
    assert await eng_repo.find_active_by_tenant(tenant_b) == []
