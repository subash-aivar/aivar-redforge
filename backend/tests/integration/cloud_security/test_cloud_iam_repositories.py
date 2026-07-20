"""PostgreSQL integration tests for M26 CloudIAMPrincipal repository."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from ulid import ULID

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.entities import PolicyAttachment, TrustRelationship
from redforge.domain.cloud_security.value_objects import (
    CloudAccountType,
    CloudProviderType,
    CredentialRef,
    IAMPrincipalType,
    OrganizationId,
    PolicyAttachmentType,
    PrivilegeLevel,
)
from redforge.infrastructure.cloud_security.persistence.repositories import (
    PgCloudAccountRepository,
    PgCloudIAMPrincipalRepository,
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
async def test_cloud_iam_principal_round_trip_and_soft_delete(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    async with session_factory() as session, session.begin():
        providers = PgCloudProviderRepository(session)
        accounts = PgCloudAccountRepository(session)
        principals = PgCloudIAMPrincipalRepository(session)
        provider = CloudProvider.register(
            organization_id=org,
            provider_type=CloudProviderType.AWS,
            display_name="IAM AWS",
        )
        await providers.save(provider)
        account = CloudAccount.register(
            cloud_provider_id=provider.id,
            organization_id=org,
            external_id="111122223333",
            display_name="Acct",
            account_type=CloudAccountType.STANDALONE,
            credential_ref=CredentialRef(reference_id="cred-iam"),
        )
        await accounts.save(account)
        principal = CloudIAMPrincipal.discover(
            cloud_account_id=account.id,
            organization_id=org,
            principal_type=IAMPrincipalType.ROLE,
            provider_id="arn:aws:iam::111122223333:role/roundtrip",
            display_name="roundtrip",
            attached_policies=[
                PolicyAttachment.create(
                    policy_provider_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
                    policy_name="ReadOnlyAccess",
                    attachment_type=PolicyAttachmentType.MANAGED,
                )
            ],
            trust_relationships=[
                TrustRelationship.create(
                    trusted_principal_provider_id="ec2.amazonaws.com",
                    trust_type="AssumeRole",
                    is_cross_account=False,
                )
            ],
            privilege_level=PrivilegeLevel.NONE,
        )
        await principals.save(principal)

    async with session_factory() as session:
        principals = PgCloudIAMPrincipalRepository(session)
        loaded = await principals.get_by_provider_id(
            account.id, "arn:aws:iam::111122223333:role/roundtrip", org
        )
        assert loaded is not None
        assert loaded.display_name == "roundtrip"
        assert loaded.privilege_level is PrivilegeLevel.NONE
        assert len(loaded.attached_policies) == 1
        assert len(loaded.trust_relationships) == 1
        # EffectivePermissions must never be mapped from DB (always unknown default).
        assert loaded.effective_permissions.actions == ()
        page = await principals.list_by_organization(org, page=1, size=20)
        assert page.total == 1

    async with session_factory() as session, session.begin():
        principals = PgCloudIAMPrincipalRepository(session)
        deleted = await principals.mark_deleted(set(), account.id, org)
        assert len(deleted) == 1
        assert deleted[0].is_deleted is True

    async with session_factory() as session:
        principals = PgCloudIAMPrincipalRepository(session)
        page = await principals.list_by_organization(org, page=1, size=20, include_deleted=False)
        assert page.total == 0
        page_all = await principals.list_by_organization(
            org, page=1, size=20, include_deleted=True
        )
        assert page_all.total == 1
