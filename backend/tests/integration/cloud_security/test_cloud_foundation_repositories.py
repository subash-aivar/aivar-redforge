"""PostgreSQL integration tests for M26 cloud foundation repositories."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.value_objects import (
    CloudAccountType,
    CloudProviderType,
    CredentialRef,
    OrganizationId,
)
from redforge.infrastructure.cloud_security.persistence.repositories import (
    PgCloudAccountRepository,
    PgCloudProviderRepository,
)

pytestmark = pytest.mark.integration

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_provider_and_account_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from ulid import ULID

    org = OrganizationId(str(ULID()))
    async with session_factory() as session, session.begin():
        providers = PgCloudProviderRepository(session)
        accounts = PgCloudAccountRepository(session)
        provider = CloudProvider.register(
            organization_id=org,
            provider_type=CloudProviderType.AWS,
            display_name="Integration AWS",
        )
        await providers.save(provider)
        account = CloudAccount.register(
            cloud_provider_id=provider.id,
            organization_id=org,
            external_id="999888777666",
            display_name="Member",
            account_type=CloudAccountType.MEMBER,
            credential_ref=CredentialRef(reference_id="vault-cred-1"),
            tags={"env": "test"},
        )
        await accounts.save(account)

    async with session_factory() as session:
        providers = PgCloudProviderRepository(session)
        accounts = PgCloudAccountRepository(session)
        loaded_provider = await providers.get_by_id(provider.id, org)
        assert loaded_provider is not None
        assert loaded_provider.display_name == "Integration AWS"
        listed = await providers.list_by_organization(org)
        assert any(item.id == provider.id for item in listed)
        loaded_account = await accounts.get_by_id(account.id, org)
        assert loaded_account is not None
        assert loaded_account.external_id == "999888777666"
        by_ext = await accounts.get_by_external_id(CloudProviderType.AWS, "999888777666", org)
        assert by_ext is not None
        page = await accounts.list_by_organization(org, page=1, size=10)
        assert page.total >= 1
        by_provider = await accounts.list_by_provider(provider.id, org)
        assert len(by_provider) >= 1
