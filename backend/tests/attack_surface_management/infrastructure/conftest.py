"""PostgreSQL fixtures for attack_surface_management infrastructure
integration tests — matches
`tests/risk_engine/infrastructure/conftest.py`'s async fixtures
exactly (`AsyncSession`/`asyncpg`, no synchronous driver)."""

from __future__ import annotations

import os
import warnings
from collections.abc import AsyncIterator, Callable

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from attack_surface_management.infrastructure.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
    make_sqlalchemy_uow_factory,
)

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


def run_alembic(*targets: str) -> None:
    os.environ["REDFORGE_DATABASE_URL"] = TEST_DATABASE_URL
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        cfg = Config("alembic.ini")
        for target in targets:
            if target.startswith("downgrade:"):
                command.downgrade(cfg, target.removeprefix("downgrade:"))
            else:
                command.upgrade(cfg, target)


@pytest.fixture(scope="session", autouse=True)
def apply_attack_surface_management_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    run_alembic("0157")
    yield


@pytest_asyncio.fixture
async def asm_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def asm_session_factory(
    asm_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(asm_engine, expire_on_commit=False)


@pytest.fixture
def asm_uow_factory(
    asm_session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], SqlAlchemyUnitOfWork]:
    return make_sqlalchemy_uow_factory(asm_session_factory)


@pytest_asyncio.fixture
async def asm_session(
    asm_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    session = asm_session_factory()
    yield session
    await session.rollback()
    await session.close()
