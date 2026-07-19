"""PostgreSQL fixtures for credential vault infrastructure integration tests."""

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

from credential_vault.infrastructure.encryption.aes_gcm_encryption_adapter import (
    AesGcmEncryptionAdapter,
)
from credential_vault.infrastructure.encryption.local_kms_adapter import LocalAesKwKmsAdapter
from credential_vault.infrastructure.persistence.unit_of_work import (
    CredentialVaultUnitOfWork,
    make_credential_vault_uow_factory,
)

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


def run_alembic(*targets: str) -> None:
    """Run Alembic against the integration test database."""
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
def apply_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    run_alembic("0045")
    yield


@pytest_asyncio.fixture
async def pg_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def pg_session_factory(
    pg_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(pg_engine, expire_on_commit=False)


@pytest.fixture
def encryption_port() -> AesGcmEncryptionAdapter:
    return AesGcmEncryptionAdapter()


@pytest.fixture
def kms_port() -> LocalAesKwKmsAdapter:
    return LocalAesKwKmsAdapter.from_env()


@pytest.fixture
def pg_uow_factory(
    pg_session_factory: async_sessionmaker[AsyncSession],
    encryption_port: AesGcmEncryptionAdapter,
    kms_port: LocalAesKwKmsAdapter,
) -> Callable[[], CredentialVaultUnitOfWork]:
    return make_credential_vault_uow_factory(pg_session_factory, encryption_port, kms_port)


@pytest_asyncio.fixture
async def pg_uow(
    pg_uow_factory: Callable[[], CredentialVaultUnitOfWork],
) -> AsyncIterator[CredentialVaultUnitOfWork]:
    uow = pg_uow_factory()
    async with uow as active:
        yield active
        await active.rollback()
