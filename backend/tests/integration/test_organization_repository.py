"""Integration tests for SqlAlchemyOrganizationRepository.

Uses an async SQLite in-memory database to test the full persistence path:
ORM model creation, entity mapping, and async session operations.

These tests validate that the repository correctly persists and reconstitutes
domain entities through the entire infrastructure stack.
"""

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
    OrganizationStatus,
)
from redforge.infrastructure.database.models import OrganizationModel
from redforge.infrastructure.database.repositories.organization_repository import (
    SqlAlchemyOrganizationRepository,
)
from redforge.shared.identifiers import EntityId


@pytest.fixture
async def session() -> AsyncSession:
    """Create an async SQLite session with schema for testing."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    async with engine.begin() as conn:
        # Scoped to this test's own table only — NOT the shared
        # `Base.metadata.create_all` — because other, unrelated bounded
        # contexts register Postgres-only column types (e.g. JSONB) on
        # that same shared metadata; if any of those modules happen to
        # already be imported (real-app-wiring tests elsewhere in the
        # suite do this), a whole-metadata create_all against this
        # SQLite engine fails to compile those columns. This repository
        # test only needs its own table.
        await conn.run_sync(OrganizationModel.__table__.create)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def repository(session: AsyncSession) -> SqlAlchemyOrganizationRepository:
    """Create a repository instance scoped to the test session."""
    return SqlAlchemyOrganizationRepository(session)


def _create_org(
    name: str = "Test Organization",
    slug: str = "test-org",
    plan: OrganizationPlan = OrganizationPlan.FREE,
) -> Organization:
    """Create a domain Organization for testing."""
    return Organization.create(
        name=OrganizationName(name),
        slug=OrganizationSlug(slug),
        plan=plan,
    )


class TestSaveOrganization:
    async def test_save_new_organization(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org()

        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert loaded.id == org.id

    async def test_save_persists_all_fields(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org(name="Acme Corp", slug="acme-corp", plan=OrganizationPlan.ENTERPRISE)

        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert str(loaded.name) == "Acme Corp"
        assert str(loaded.slug) == "acme-corp"
        assert loaded.status == OrganizationStatus.ACTIVE
        assert loaded.plan == OrganizationPlan.ENTERPRISE
        assert loaded.timestamps.created_at is not None
        assert loaded.timestamps.updated_at is not None


class TestGetById:
    async def test_returns_none_when_not_found(
        self, repository: SqlAlchemyOrganizationRepository
    ) -> None:
        result = await repository.get_by_id(EntityId.generate())
        assert result is None

    async def test_returns_entity_when_found(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org()
        await repository.save(org)
        await session.commit()

        result = await repository.get_by_id(org.id)
        assert result is not None
        assert result.id == org.id
        assert str(result.name) == "Test Organization"


class TestGetBySlug:
    async def test_returns_none_when_not_found(
        self, repository: SqlAlchemyOrganizationRepository
    ) -> None:
        result = await repository.get_by_slug(OrganizationSlug("nonexistent"))
        assert result is None

    async def test_returns_entity_when_found(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org(slug="my-org")
        await repository.save(org)
        await session.commit()

        result = await repository.get_by_slug(OrganizationSlug("my-org"))
        assert result is not None
        assert str(result.slug) == "my-org"


class TestSlugExists:
    async def test_returns_false_when_available(
        self, repository: SqlAlchemyOrganizationRepository
    ) -> None:
        exists = await repository.slug_exists(OrganizationSlug("available"))
        assert exists is False

    async def test_returns_true_when_taken(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org(slug="taken")
        await repository.save(org)
        await session.commit()

        exists = await repository.slug_exists(OrganizationSlug("taken"))
        assert exists is True


class TestUpdateOrganization:
    async def test_update_name(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org(name="Old Name")
        await repository.save(org)
        await session.commit()

        org.rename(OrganizationName("New Name"))
        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert str(loaded.name) == "New Name"

    async def test_update_preserves_id(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org()
        original_id = org.id
        await repository.save(org)
        await session.commit()

        org.rename(OrganizationName("Updated"))
        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(original_id)
        assert loaded is not None
        assert loaded.id == original_id


class TestPersistPlanChange:
    async def test_persist_plan_upgrade(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org(plan=OrganizationPlan.FREE)
        await repository.save(org)
        await session.commit()

        org.change_plan(OrganizationPlan.ENTERPRISE)
        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert loaded.plan == OrganizationPlan.ENTERPRISE

    async def test_persist_plan_downgrade(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org(plan=OrganizationPlan.ENTERPRISE)
        await repository.save(org)
        await session.commit()

        org.change_plan(OrganizationPlan.STARTER)
        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert loaded.plan == OrganizationPlan.STARTER


class TestPersistStatusChange:
    async def test_persist_deactivation(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org()
        await repository.save(org)
        await session.commit()

        org.deactivate()
        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert loaded.status == OrganizationStatus.INACTIVE
        assert loaded.is_active is False

    async def test_persist_reactivation(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org()
        org.deactivate()
        await repository.save(org)
        await session.commit()

        org.activate()
        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert loaded.status == OrganizationStatus.ACTIVE
        assert loaded.is_active is True

    async def test_updated_at_advances_on_status_change(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org = _create_org()
        await repository.save(org)
        await session.commit()

        org.deactivate()
        await repository.save(org)
        await session.commit()

        loaded = await repository.get_by_id(org.id)
        assert loaded is not None
        assert loaded.timestamps.updated_at >= loaded.timestamps.created_at


class TestSlugUniqueness:
    async def test_duplicate_slug_raises(
        self, repository: SqlAlchemyOrganizationRepository, session: AsyncSession
    ) -> None:
        org1 = _create_org(slug="unique-slug")
        await repository.save(org1)
        await session.commit()

        org2 = Organization.create(
            name=OrganizationName("Other Org"),
            slug=OrganizationSlug("unique-slug"),
            plan=OrganizationPlan.FREE,
        )

        with pytest.raises(IntegrityError):
            await repository.save(org2)
