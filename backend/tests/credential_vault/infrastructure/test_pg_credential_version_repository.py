"""Integration tests for PgCredentialVersionRepository."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid7

import pytest
from tests.credential_vault.infrastructure.repository_helpers import (
    make_credential,
    make_version,
    register_backend,
)

from credential_vault.domain.exceptions.domain_exceptions import (
    ActiveVersionNotFound,
    OptimisticLockConflict,
)
from credential_vault.domain.value_objects.identifiers import TenantId
from credential_vault.domain.value_objects.states import VersionState

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_save_and_get_by_id(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        version = make_version(cred, now, number=1)
        await uow.credentials.save(cred)
        await uow.versions.save(version)
        await uow.commit()

    async with pg_uow_factory() as uow:
        loaded = await uow.versions.get_by_id(version.version_id, tenant_id)
        assert loaded.version_id == version.version_id
        assert loaded.credential_id == cred.credential_id
        assert loaded.version_number == 1
        assert loaded.version_state == VersionState.ACTIVE
        assert loaded.encrypted_payload.algorithm == "AES-256-GCM"
        await uow.rollback()


@pytest.mark.asyncio
async def test_get_active_version_returns_correct_state(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        active = make_version(cred, now, state=VersionState.ACTIVE, number=1)
        pending = make_version(cred, now, state=VersionState.PENDING, number=2)
        await uow.credentials.save(cred)
        await uow.versions.save(active)
        await uow.versions.save(pending)
        await uow.commit()

    async with pg_uow_factory() as uow:
        loaded = await uow.versions.get_active_version(cred.credential_id, tenant_id)
        assert loaded.version_id == active.version_id
        assert loaded.version_state == VersionState.ACTIVE
        await uow.rollback()


@pytest.mark.asyncio
async def test_get_active_version_raises_if_no_active(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        pending = make_version(cred, now, state=VersionState.PENDING, number=1)
        await uow.credentials.save(cred)
        await uow.versions.save(pending)
        await uow.commit()

    async with pg_uow_factory() as uow:
        with pytest.raises(ActiveVersionNotFound):
            await uow.versions.get_active_version(cred.credential_id, tenant_id)
        await uow.rollback()


@pytest.mark.asyncio
async def test_list_by_credential_ordered_ascending_version_number(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        v3 = make_version(cred, now, state=VersionState.SUPERSEDED, number=3)
        v1 = make_version(cred, now, state=VersionState.SUPERSEDED, number=1)
        v2 = make_version(cred, now, state=VersionState.ACTIVE, number=2)
        await uow.credentials.save(cred)
        for version in (v3, v1, v2):
            await uow.versions.save(version)
        await uow.commit()

    async with pg_uow_factory() as uow:
        versions = await uow.versions.list_by_credential(cred.credential_id, tenant_id)
        assert [item.version_number for item in versions] == [1, 2, 3]
        await uow.rollback()


@pytest.mark.asyncio
async def test_list_by_credential_with_state_filter(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        active = make_version(cred, now, state=VersionState.ACTIVE, number=1)
        pending = make_version(cred, now, state=VersionState.PENDING, number=2)
        superseded = make_version(cred, now, state=VersionState.SUPERSEDED, number=3)
        await uow.credentials.save(cred)
        for version in (active, pending, superseded):
            await uow.versions.save(version)
        await uow.commit()

    async with pg_uow_factory() as uow:
        pending_only = await uow.versions.list_by_credential(
            cred.credential_id,
            tenant_id,
            states=[VersionState.PENDING],
        )
        assert [item.version_number for item in pending_only] == [2]
        await uow.rollback()


@pytest.mark.asyncio
async def test_atomic_promote_sets_new_active_and_supersedes_old(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        v1 = make_version(cred, now, state=VersionState.ACTIVE, number=1)
        cred.active_version_id = v1.version_id
        await uow.credentials.save(cred)
        await uow.versions.save(v1)
        await uow.commit()

    async with pg_uow_factory() as uow:
        v2 = make_version(cred, now, state=VersionState.PENDING, number=2)
        await uow.versions.save(v2)
        await uow.versions.atomic_promote(v2, v1.version_id, tenant_id)
        await uow.commit()

    async with pg_uow_factory() as uow:
        active = await uow.versions.get_active_version(cred.credential_id, tenant_id)
        assert active.version_id == v2.version_id
        old = await uow.versions.get_by_id(v1.version_id, tenant_id)
        assert old.version_state == VersionState.SUPERSEDED
        await uow.rollback()


@pytest.mark.asyncio
async def test_atomic_promote_raises_if_no_active_to_supersede(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        pending = make_version(cred, now, state=VersionState.PENDING, number=1)
        promote_target = make_version(cred, now, state=VersionState.PENDING, number=2)
        await uow.credentials.save(cred)
        await uow.versions.save(pending)
        await uow.versions.save(promote_target)
        await uow.commit()

    async with pg_uow_factory() as uow:
        with pytest.raises(OptimisticLockConflict):
            await uow.versions.atomic_promote(promote_target, pending.version_id, tenant_id)
        await uow.rollback()


@pytest.mark.asyncio
async def test_update_increments_row_version(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        version = make_version(cred, now, state=VersionState.PENDING, number=1)
        await uow.credentials.save(cred)
        await uow.versions.save(version)
        await uow.commit()

    async with pg_uow_factory() as uow:
        loaded = await uow.versions.get_by_id(version.version_id, tenant_id)
        loaded.version_state = VersionState.REVOKED
        await uow.versions.update(loaded)
        await uow.commit()

    async with pg_uow_factory() as uow:
        reloaded = await uow.versions.get_by_id(version.version_id, tenant_id)
        assert reloaded.version_state == VersionState.REVOKED
        await uow.rollback()


@pytest.mark.asyncio
async def test_update_raises_optimistic_lock_conflict(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        version = make_version(cred, now, state=VersionState.PENDING, number=1)
        await uow.credentials.save(cred)
        await uow.versions.save(version)
        await uow.commit()

    async with pg_uow_factory() as uow1:
        v1 = await uow1.versions.get_by_id(version.version_id, tenant_id)
        async with pg_uow_factory() as uow2:
            v2 = await uow2.versions.get_by_id(version.version_id, tenant_id)
            v2.version_state = VersionState.REVOKED
            await uow2.versions.update(v2)
            await uow2.commit()
        v1.version_state = VersionState.SUPERSEDED
        with pytest.raises(OptimisticLockConflict):
            await uow1.versions.update(v1)
        await uow1.rollback()


@pytest.mark.asyncio
async def test_count_superseded_returns_correct_count(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        v1 = make_version(cred, now, state=VersionState.ACTIVE, number=1)
        await uow.credentials.save(cred)
        await uow.versions.save(v1)
        await uow.commit()

    async with pg_uow_factory() as uow:
        v2 = make_version(cred, now, state=VersionState.PENDING, number=2)
        await uow.versions.save(v2)
        await uow.versions.atomic_promote(v2, v1.version_id, tenant_id)
        await uow.commit()

    async with pg_uow_factory() as uow:
        count = await uow.versions.count_superseded(cred.credential_id, tenant_id)
        assert count == 1
        await uow.rollback()
