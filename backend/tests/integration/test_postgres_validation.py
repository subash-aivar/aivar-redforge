"""PostgreSQL integration validation tests.

These tests verify database behavior against a real PostgreSQL instance.
They run in CI with the postgres service container.

Validates:
- Transaction rollback via UnitOfWork
- Concurrent session isolation
- Constraint enforcement (unique slug, unique email)

Skipped locally if REDFORGE_DATABASE_URL does not point to PostgreSQL.
"""

import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (
    AITargetModel,  # noqa: F401
    OrganizationModel,  # noqa: F401
    UserModel,  # noqa: F401
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

_INSERT_ORG = text(
    "INSERT INTO organizations "
    "(id, name, slug, status, plan, created_at, updated_at) "
    "VALUES (:id, :name, :slug, :status, :plan, NOW(), NOW())"
)

_INSERT_USER = text(
    "INSERT INTO users "
    "(id, email, display_name, status, created_at, updated_at) "
    "VALUES (:id, :email, :name, :status, NOW(), NOW())"
)


def _is_postgres() -> bool:
    """Check if we're running against PostgreSQL."""
    import os

    url = os.environ.get("REDFORGE_DATABASE_URL", "")
    return "postgresql" in url or "postgres" in url


pytestmark = pytest.mark.skipif(
    not _is_postgres(),
    reason="Requires PostgreSQL (set REDFORGE_DATABASE_URL)",
)


@pytest.fixture
async def pg_engine():
    """Create a test engine against the real PostgreSQL."""
    import os

    url = os.environ["REDFORGE_DATABASE_URL"]
    engine = create_async_engine(url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
def session_factory(pg_engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        pg_engine, class_=AsyncSession, expire_on_commit=False
    )


class TestTransactionRollback:
    """Verify UnitOfWork rollback on PostgreSQL."""

    async def test_rollback_on_exception(self, session_factory) -> None:
        """Data is NOT persisted when exception occurs within UoW."""
        org_id = "01ROLLBACK00000000000000001"

        with pytest.raises(ValueError, match="deliberate"):
            async with SessionUnitOfWork(session_factory) as uow:
                await uow.session.execute(
                    _INSERT_ORG,
                    {
                        "id": org_id, "name": "Rollback Corp",
                        "slug": "rollback-corp", "status": "active",
                        "plan": "free",
                    },
                )
                raise ValueError("deliberate failure")

        async with session_factory() as session:
            result = await session.execute(
                text("SELECT id FROM organizations WHERE id = :id"),
                {"id": org_id},
            )
            assert result.first() is None

    async def test_commit_persists_data(self, session_factory) -> None:
        """Data IS persisted when commit() is called."""
        org_id = "01COMMIT000000000000000001"

        async with SessionUnitOfWork(session_factory) as uow:
            await uow.session.execute(
                _INSERT_ORG,
                {
                    "id": org_id, "name": "Commit Corp",
                    "slug": "commit-corp", "status": "active",
                    "plan": "enterprise",
                },
            )
            await uow.commit()

        async with session_factory() as session:
            result = await session.execute(
                text("SELECT name FROM organizations WHERE id = :id"),
                {"id": org_id},
            )
            row = result.first()
            assert row is not None
            assert row[0] == "Commit Corp"


class TestConcurrentSessions:
    """Verify session isolation under concurrent access."""

    async def test_concurrent_uow_isolation(self, session_factory) -> None:
        """Two concurrent UoW instances don't interfere."""
        org_id_a = "01CONCURRA0000000000000001"
        org_id_b = "01CONCURRB0000000000000001"

        async def writer_a():
            async with SessionUnitOfWork(session_factory) as uow:
                await uow.session.execute(
                    _INSERT_ORG,
                    {
                        "id": org_id_a, "name": "A Corp",
                        "slug": "a-corp", "status": "active",
                        "plan": "free",
                    },
                )
                await asyncio.sleep(0.05)
                await uow.commit()

        async def writer_b():
            async with SessionUnitOfWork(session_factory) as uow:
                await uow.session.execute(
                    _INSERT_ORG,
                    {
                        "id": org_id_b, "name": "B Corp",
                        "slug": "b-corp", "status": "active",
                        "plan": "free",
                    },
                )
                await uow.commit()

        await asyncio.gather(writer_a(), writer_b())

        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT COUNT(*) FROM organizations "
                    "WHERE id IN (:a, :b)"
                ),
                {"a": org_id_a, "b": org_id_b},
            )
            assert result.scalar() == 2


class TestConstraints:
    """Verify database constraints are enforced."""

    async def test_unique_slug_constraint(self, session_factory) -> None:
        """Duplicate slug raises IntegrityError."""
        from sqlalchemy.exc import IntegrityError

        async with SessionUnitOfWork(session_factory) as uow:
            await uow.session.execute(
                _INSERT_ORG,
                {
                    "id": "01UNIQUE100000000000000001",
                    "name": "First", "slug": "unique-slug",
                    "status": "active", "plan": "free",
                },
            )
            await uow.commit()

        with pytest.raises(IntegrityError):
            async with SessionUnitOfWork(session_factory) as uow:
                await uow.session.execute(
                    _INSERT_ORG,
                    {
                        "id": "01UNIQUE200000000000000001",
                        "name": "Second", "slug": "unique-slug",
                        "status": "active", "plan": "free",
                    },
                )
                await uow.commit()

    async def test_user_unique_email_constraint(
        self, session_factory
    ) -> None:
        """Duplicate email raises IntegrityError."""
        from sqlalchemy.exc import IntegrityError

        async with SessionUnitOfWork(session_factory) as uow:
            await uow.session.execute(
                _INSERT_USER,
                {
                    "id": "01EMAILU10000000000000001",
                    "email": "dup@test.com",
                    "name": "First", "status": "active",
                },
            )
            await uow.commit()

        with pytest.raises(IntegrityError):
            async with SessionUnitOfWork(session_factory) as uow:
                await uow.session.execute(
                    _INSERT_USER,
                    {
                        "id": "01EMAILU20000000000000001",
                        "email": "dup@test.com",
                        "name": "Second", "status": "active",
                    },
                )
                await uow.commit()
