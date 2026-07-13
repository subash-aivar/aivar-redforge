"""Integration tests for Application Services.

Tests the full coordination: session → repository → domain → commit → events.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.ai_targets import AITargetService
from redforge.application.organizations import OrganizationService
from redforge.domain.organizations.exceptions import (
    OrganizationNotFoundError,
    OrganizationSlugTakenError,
)
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AITargetModel,
    MembershipModel,
    OrganizationModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.shared.identifiers import EntityId

_CREATOR_ID = str(EntityId.generate())


@pytest.fixture
async def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def events() -> InMemoryEventPublisher:
    return InMemoryEventPublisher()


class TestOrganizationService:
    async def test_register(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        svc = OrganizationService(session_factory, events)
        dto = await svc.register(
            "Acme Corp", "acme-corp", "enterprise", created_by_user_id=_CREATOR_ID,
        )
        assert dto.name == "Acme Corp"
        assert dto.slug == "acme-corp"
        assert dto.plan == "enterprise"
        assert dto.status == "active"
        # OrganizationCreated + the auto-granted OWNER MembershipCreated.
        assert len(events.published) == 2

    async def test_register_duplicate_slug_raises(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        svc = OrganizationService(session_factory, events)
        await svc.register("First", "unique-slug", created_by_user_id=_CREATOR_ID)
        with pytest.raises(OrganizationSlugTakenError):
            await svc.register("Second", "unique-slug", created_by_user_id=_CREATOR_ID)

    async def test_get_by_id(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        svc = OrganizationService(session_factory, events)
        created = await svc.register("Get Test", "get-test", created_by_user_id=_CREATOR_ID)
        loaded = await svc.get_by_id(created.id)
        assert loaded.name == "Get Test"

    async def test_get_not_found_raises(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        svc = OrganizationService(session_factory, events)
        with pytest.raises(OrganizationNotFoundError):
            await svc.get_by_id(str(EntityId.generate()))

    async def test_rename(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        svc = OrganizationService(session_factory, events)
        created = await svc.register("Old Name", "old-name", created_by_user_id=_CREATOR_ID)
        events.clear()
        renamed = await svc.rename(created.id, "New Name")
        assert renamed.name == "New Name"
        assert len(events.published) == 1

    async def test_deactivate_and_activate(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        svc = OrganizationService(session_factory, events)
        created = await svc.register("Active Org", "active-org", created_by_user_id=_CREATOR_ID)
        deactivated = await svc.deactivate(created.id)
        assert deactivated.status == "inactive"
        activated = await svc.activate(created.id)
        assert activated.status == "active"


class TestAITargetService:
    async def test_register_target(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        org_svc = OrganizationService(session_factory, events)
        org = await org_svc.register("Target Org", "target-org", created_by_user_id=_CREATOR_ID)
        events.clear()

        target_svc = AITargetService(session_factory, events)
        dto = await target_svc.register(
            organization_id=org.id,
            name="Production LLM",
            description="Customer chatbot",
            target_type="llm_application",
            provider="openai",
            endpoint="https://api.acme.com/chat",
        )
        assert dto.name == "Production LLM"
        assert dto.target_type == "llm_application"
        assert dto.status == "active"
        assert len(events.published) == 1

    async def test_get_target(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        org_svc = OrganizationService(session_factory, events)
        org = await org_svc.register("Get Org", "get-org", created_by_user_id=_CREATOR_ID)

        target_svc = AITargetService(session_factory, events)
        created = await target_svc.register(
            organization_id=org.id,
            name="Get Target",
            description="",
            target_type="ai_agent",
            provider="anthropic",
            endpoint="https://api.test.com/v1",
        )
        loaded = await target_svc.get_by_id(created.id, org.id)
        assert loaded.name == "Get Target"

    async def test_list_by_org(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        org_svc = OrganizationService(session_factory, events)
        org = await org_svc.register("List Org", "list-org", created_by_user_id=_CREATOR_ID)

        target_svc = AITargetService(session_factory, events)
        await target_svc.register(
            organization_id=org.id, name="T1", description="",
            target_type="llm_application", provider="openai",
            endpoint="https://a.com",
        )
        await target_svc.register(
            organization_id=org.id, name="T2", description="",
            target_type="rag_system", provider="anthropic",
            endpoint="https://b.com",
        )
        targets = await target_svc.list_by_organization(org.id)
        assert len(targets) == 2

    async def test_deactivate_target(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        events: InMemoryEventPublisher,
    ) -> None:
        org_svc = OrganizationService(session_factory, events)
        org = await org_svc.register("Deact Org", "deact-org", created_by_user_id=_CREATOR_ID)

        target_svc = AITargetService(session_factory, events)
        created = await target_svc.register(
            organization_id=org.id, name="To Deactivate", description="",
            target_type="mcp_server", provider="custom",
            endpoint="https://mcp.local",
        )
        deactivated = await target_svc.deactivate(created.id, org.id)
        assert deactivated.status == "inactive"
