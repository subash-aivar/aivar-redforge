"""PostgreSQL integration tests for M26 CloudAsset repository."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from ulid import ULID

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_asset import CloudAsset, relationship
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.entities import CloudRegion
from redforge.domain.cloud_security.value_objects import (
    CloudAccountType,
    CloudAssetRelationshipType,
    CloudAssetType,
    CloudProviderType,
    CredentialRef,
    NetworkExposure,
    NormalizedConfig,
    OrganizationId,
    ProviderMetadata,
)
from redforge.infrastructure.cloud_security.persistence.repositories import (
    PgCloudAccountRepository,
    PgCloudAssetRepository,
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


def _norm(resource_class: str = "compute") -> NormalizedConfig:
    return NormalizedConfig(
        schema_version="1",
        resource_class=resource_class,
        network_exposure=NetworkExposure.PRIVATE,
    )


@pytest.mark.asyncio
async def test_cloud_asset_round_trip_and_soft_delete(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    async with session_factory() as session, session.begin():
        providers = PgCloudProviderRepository(session)
        accounts = PgCloudAccountRepository(session)
        assets = PgCloudAssetRepository(session)
        provider = CloudProvider.register(
            organization_id=org,
            provider_type=CloudProviderType.AWS,
            display_name="Asset AWS",
        )
        await providers.save(provider)
        account = CloudAccount.register(
            cloud_provider_id=provider.id,
            organization_id=org,
            external_id="111122223333",
            display_name="Acct",
            account_type=CloudAccountType.STANDALONE,
            credential_ref=CredentialRef(reference_id="cred-asset"),
        )
        await accounts.save(account)
        asset = CloudAsset.discover(
            cloud_account_id=account.id,
            organization_id=org,
            asset_type=CloudAssetType.EC2_INSTANCE,
            provider_id="i-roundtrip",
            region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
            display_name="web",
            provider_metadata=ProviderMetadata.from_dict({"instance_type": "t3.micro"}),
            normalized_config=_norm(),
            tags={"env": "test"},
            relationships=[
                relationship(
                    relationship_type=CloudAssetRelationshipType.CONTAINED_IN,
                    target_provider_id="vpc-1",
                )
            ],
        )
        await assets.save(asset)

    async with session_factory() as session:
        assets = PgCloudAssetRepository(session)
        loaded = await assets.get_by_provider_id(account.id, "i-roundtrip", org)
        assert loaded is not None
        assert loaded.display_name == "web"
        assert loaded.tags["env"] == "test"
        assert len(loaded.relationships) == 1
        page = await assets.list_by_organization(org, page=1, size=20)
        assert page.total == 1

    async with session_factory() as session, session.begin():
        assets = PgCloudAssetRepository(session)
        deleted = await assets.mark_deleted(set(), account.id, org)
        assert len(deleted) == 1
        assert deleted[0].is_deleted is True

    async with session_factory() as session:
        assets = PgCloudAssetRepository(session)
        page = await assets.list_by_organization(org, page=1, size=20, include_deleted=False)
        assert page.total == 0
        page_all = await assets.list_by_organization(org, page=1, size=20, include_deleted=True)
        assert page_all.total == 1
