"""Integration tests for SqlAlchemyAITargetRepository."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.domain.ai_targets.entity import AITarget
from redforge.domain.ai_targets.value_objects import (
    EndpointUrl,
    Provider,
    Tag,
    TargetName,
    TargetStatus,
    TargetType,
)
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import AITargetModel  # noqa: F401
from redforge.infrastructure.database.repositories.ai_target_repository import (
    SqlAlchemyAITargetRepository,
)
from redforge.shared.identifiers import EntityId


@pytest.fixture
async def session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def repository(session: AsyncSession) -> SqlAlchemyAITargetRepository:
    return SqlAlchemyAITargetRepository(session)


def _create_target(org_id: EntityId | None = None) -> AITarget:
    return AITarget.register(
        organization_id=org_id or EntityId.generate(),
        name=TargetName("Test LLM App"),
        description="A test target",
        target_type=TargetType.LLM_APPLICATION,
        provider=Provider.OPENAI,
        endpoint=EndpointUrl("https://api.test.com/v1"),
    )


class TestSave:
    async def test_saves_and_loads(
        self, repository: SqlAlchemyAITargetRepository, session: AsyncSession
    ) -> None:
        target = _create_target()
        await repository.save(target)
        await session.commit()

        loaded = await repository.get_by_id(target.id, target.organization_id)
        assert loaded is not None
        assert str(loaded.name) == "Test LLM App"
        assert loaded.target_type == TargetType.LLM_APPLICATION
        assert loaded.provider == Provider.OPENAI

    async def test_persists_tags(
        self, repository: SqlAlchemyAITargetRepository, session: AsyncSession
    ) -> None:
        target = _create_target()
        target.add_tag(Tag("env:production"))
        target.add_tag(Tag("team:security"))
        await repository.save(target)
        await session.commit()

        loaded = await repository.get_by_id(target.id, target.organization_id)
        assert loaded is not None
        assert Tag("env:production") in loaded.tags
        assert Tag("team:security") in loaded.tags


class TestGetByIdOrganizationScoping:
    async def test_cross_organization_lookup_returns_none(
        self, repository: SqlAlchemyAITargetRepository, session: AsyncSession
    ) -> None:
        """A target's ID is valid, but looking it up with the WRONG
        organization_id must behave identically to a nonexistent ID —
        this is the structural IDOR fix at the repository layer."""
        owner_org = EntityId.generate()
        attacker_org = EntityId.generate()
        target = _create_target(owner_org)
        await repository.save(target)
        await session.commit()

        as_owner = await repository.get_by_id(target.id, owner_org)
        assert as_owner is not None

        as_attacker = await repository.get_by_id(target.id, attacker_org)
        assert as_attacker is None

    async def test_nonexistent_id_also_returns_none(
        self, repository: SqlAlchemyAITargetRepository, session: AsyncSession
    ) -> None:
        """Nonexistent-ID and wrong-org-ID must be indistinguishable to
        the caller — no information leak about which org owns an ID."""
        result = await repository.get_by_id(EntityId.generate(), EntityId.generate())
        assert result is None


class TestListByOrganization:
    async def test_filters_by_org(
        self, repository: SqlAlchemyAITargetRepository, session: AsyncSession
    ) -> None:
        org_id = EntityId.generate()
        t1 = _create_target(org_id)
        t2 = _create_target(org_id)
        t3 = _create_target(EntityId.generate())  # different org
        await repository.save(t1)
        await repository.save(t2)
        await repository.save(t3)
        await session.commit()

        results = await repository.list_by_organization(org_id)
        assert len(results) == 2

    async def test_filters_by_status(
        self, repository: SqlAlchemyAITargetRepository, session: AsyncSession
    ) -> None:
        org_id = EntityId.generate()
        t1 = _create_target(org_id)
        t2 = _create_target(org_id)
        t2.deactivate()
        await repository.save(t1)
        await repository.save(t2)
        await session.commit()

        active = await repository.list_by_organization(org_id, status=TargetStatus.ACTIVE)
        assert len(active) == 1


class TestUpdate:
    async def test_updates_status(
        self, repository: SqlAlchemyAITargetRepository, session: AsyncSession
    ) -> None:
        target = _create_target()
        await repository.save(target)
        await session.commit()

        target.deactivate()
        await repository.save(target)
        await session.commit()

        loaded = await repository.get_by_id(target.id, target.organization_id)
        assert loaded is not None
        assert loaded.status == TargetStatus.INACTIVE
