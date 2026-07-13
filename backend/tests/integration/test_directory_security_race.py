"""Real-PostgreSQL concurrency proof for Directory Security resolution — M5.

Proves the mandatory M5 concurrency invariants:
  1. Concurrent resolution of the SAME (organization_id, connector_id,
     external_id) identity produces exactly one canonical identity.
  2. The SAME external identity across two DIFFERENT organizations
     remains fully independent.
  3. Concurrent resolution of the SAME group key produces exactly one
     canonical group.
  4. Concurrent observation of the SAME membership produces exactly
     one canonical membership row.
  5. Cross-tenant membership is rejected by the DATABASE itself
     (composite foreign key), not merely application logic.

Runs against a dedicated, self-created database
(`redforge_directory_security_race_test`), never the shared dev
database.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.directory_security import (
    DirectoryGroupModel,
    DirectoryIdentityModel,
    DirectoryMembershipModel,
)
from redforge.infrastructure.database.repositories.directory_security_repository import (
    DirectorySecurityRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_directory_security_race_test"
_MAINTENANCE_DB_URL = os.environ.get(
    "REDFORGE_MAINTENANCE_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/postgres",
)
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)


async def _ensure_test_database_exists() -> None:
    maintenance_engine = create_async_engine(
        _MAINTENANCE_DB_URL, echo=False, isolation_level="AUTOCOMMIT",
    )
    try:
        async with maintenance_engine.connect() as conn:
            exists = await conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": _TEST_DB_NAME},
            )
            if exists.first() is None:
                await conn.execute(text(f'CREATE DATABASE "{_TEST_DB_NAME}"'))
    finally:
        await maintenance_engine.dispose()


@pytest.fixture
async def pg_factory():
    await _ensure_test_database_exists()

    engine = create_async_engine(_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[
                DirectoryIdentityModel.__table__,
                DirectoryGroupModel.__table__,
                DirectoryMembershipModel.__table__,
            ],
        )
        # ORM metadata (used by create_all) doesn't carry the
        # tenant-scoped unique indexes defined only in migration 0015 —
        # create them explicitly, matching the M3/M4 test precedent.
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_dir_identities_org_conn_ext_test "
                "ON directory_identities (organization_id, connector_id, external_id)"
            )
        )
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_dir_groups_org_conn_ext_test "
                "ON directory_groups (organization_id, connector_id, external_id)"
            )
        )
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_dir_memberships_org_identity_group_test "
                "ON directory_memberships (organization_id, identity_id, group_id)"
            )
        )
        await conn.execute(text("DELETE FROM directory_memberships"))
        await conn.execute(text("DELETE FROM directory_groups"))
        await conn.execute(text("DELETE FROM directory_identities"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS directory_memberships CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS directory_groups CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS directory_identities CASCADE"))
    await engine.dispose()


async def _upsert_identity(pg_factory, organization_id: str, connector_id: str, external_id: str) -> str:
    async with SessionUnitOfWork(pg_factory) as uow:
        repo = DirectorySecurityRepository(uow.session)
        model = await repo.upsert_identity(
            identity_id=str(EntityId.generate()), organization_id=organization_id,
            connector_id=connector_id, external_id=external_id,
            principal_category="human", display_name="Concurrent Identity",
            principal_name="concurrent", source_enabled=True,
            privilege_classification="standard", privilege_reason="",
            observation_lifecycle="active", safe_attributes={},
        )
        await uow.commit()
        return model.id


async def test_concurrent_same_identity_produces_exactly_one_row(pg_factory):
    org_id = str(EntityId.generate())
    connector_id = str(EntityId.generate())
    external_id = "ldap_entry_uuid:550e8400-e29b-41d4-a716-446655440000"

    results = await asyncio.gather(
        *(_upsert_identity(pg_factory, org_id, connector_id, external_id) for _ in range(10))
    )
    assert len(set(results)) == 1

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(DirectoryIdentityModel.id)).where(
                DirectoryIdentityModel.organization_id == org_id,
            )
        )
        assert result.scalar_one() == 1


async def test_same_external_identity_across_orgs_remains_separate(pg_factory):
    connector_id = str(EntityId.generate())
    external_id = "ldap_entry_uuid:550e8400-e29b-41d4-a716-446655440001"
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())

    results = await asyncio.gather(
        *(_upsert_identity(pg_factory, org_a, connector_id, external_id) for _ in range(5)),
        *(_upsert_identity(pg_factory, org_b, connector_id, external_id) for _ in range(5)),
    )
    a_ids = {r for i, r in enumerate(results) if i < 5}
    b_ids = {r for i, r in enumerate(results) if i >= 5}
    assert len(a_ids) == 1
    assert len(b_ids) == 1
    assert a_ids != b_ids

    async with pg_factory() as session:
        result = await session.execute(select(func.count(DirectoryIdentityModel.id)))
        assert result.scalar_one() == 2


async def test_concurrent_same_group_produces_exactly_one_row(pg_factory):
    org_id = str(EntityId.generate())
    connector_id = str(EntityId.generate())
    external_id = "ldap_entry_uuid:660e8400-e29b-41d4-a716-446655440002"

    async def upsert() -> str:
        async with SessionUnitOfWork(pg_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            model = await repo.upsert_group(
                group_id=str(EntityId.generate()), organization_id=org_id,
                connector_id=connector_id, external_id=external_id,
                display_name="Concurrent Group", is_recognized_privileged=False,
            )
            await uow.commit()
            return model.id

    results = await asyncio.gather(*(upsert() for _ in range(10)))
    assert len(set(results)) == 1

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(DirectoryGroupModel.id)).where(
                DirectoryGroupModel.organization_id == org_id,
            )
        )
        assert result.scalar_one() == 1


async def test_concurrent_same_membership_produces_exactly_one_row(pg_factory):
    org_id = str(EntityId.generate())
    connector_id = str(EntityId.generate())
    identity_id = await _upsert_identity(pg_factory, org_id, connector_id, "ldap_entry_uuid:id-1")

    async with SessionUnitOfWork(pg_factory) as uow:
        repo = DirectorySecurityRepository(uow.session)
        group_model = await repo.upsert_group(
            group_id=str(EntityId.generate()), organization_id=org_id,
            connector_id=connector_id, external_id="ldap_entry_uuid:group-1",
            display_name="Group", is_recognized_privileged=False,
        )
        await uow.commit()
        group_id = group_model.id

    async def upsert_membership() -> str:
        async with SessionUnitOfWork(pg_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            model = await repo.upsert_membership(
                membership_id=str(EntityId.generate()), organization_id=org_id,
                identity_id=identity_id, group_id=group_id, provenance="test",
            )
            await uow.commit()
            return model.id

    results = await asyncio.gather(*(upsert_membership() for _ in range(10)))
    assert len(set(results)) == 1

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(DirectoryMembershipModel.id)).where(
                DirectoryMembershipModel.organization_id == org_id,
            )
        )
        assert result.scalar_one() == 1


async def test_cross_tenant_membership_rejected_by_database(pg_factory):
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())
    connector_a = str(EntityId.generate())
    connector_b = str(EntityId.generate())

    identity_a = await _upsert_identity(pg_factory, org_a, connector_a, "ldap_entry_uuid:id-a")

    async with SessionUnitOfWork(pg_factory) as uow:
        repo = DirectorySecurityRepository(uow.session)
        group_b = await repo.upsert_group(
            group_id=str(EntityId.generate()), organization_id=org_b,
            connector_id=connector_b, external_id="ldap_entry_uuid:group-b",
            display_name="Group B", is_recognized_privileged=False,
        )
        await uow.commit()
        group_b_id = group_b.id

    async with SessionUnitOfWork(pg_factory) as uow:
        repo = DirectorySecurityRepository(uow.session)
        with pytest.raises(IntegrityError):
            await repo.upsert_membership(
                membership_id=str(EntityId.generate()), organization_id=org_a,
                identity_id=identity_a, group_id=group_b_id,  # belongs to org_b, not org_a
                provenance="test",
            )
