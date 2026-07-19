"""Integration tests for PgCredentialRepository."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4, uuid7

import pytest
from tests.credential_vault.infrastructure.repository_helpers import (
    make_credential,
    register_backend,
    register_rotation_policy,
)

from credential_vault.domain.exceptions.domain_exceptions import (
    CredentialNotFound,
    OptimisticLockConflict,
)
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.credential_type import CredentialCategory, CredentialType
from credential_vault.domain.value_objects.identifiers import TenantId
from credential_vault.domain.value_objects.states import CredentialState

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_save_and_get_by_id_round_trip(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(
            tenant_id,
            backend.backend_id,
            now,
            name="round-trip-cred",
            description="detailed description",
            tags={"team": "platform"},
        )
        await uow.credentials.save(cred)
        await uow.commit()

    async with pg_uow_factory() as uow:
        loaded = await uow.credentials.get_by_id(cred.credential_id, tenant_id)
        assert loaded.credential_id == cred.credential_id
        assert loaded.tenant_id == tenant_id
        assert loaded.name.value == "round-trip-cred"
        assert loaded.credential_type == CredentialType(CredentialCategory.API_KEY, "OPENAI", None)
        assert loaded.state == CredentialState.ACTIVE
        assert loaded.vault_backend_id == backend.backend_id
        assert loaded.description == "detailed description"
        assert loaded.tags == {"team": "platform"}
        assert loaded.version == 1
        await uow.rollback()


@pytest.mark.asyncio
async def test_save_increments_row_version(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        await uow.credentials.save(cred)
        await uow.commit()

    async with pg_uow_factory() as uow:
        loaded = await uow.credentials.get_by_id(cred.credential_id, tenant_id)
        loaded.description = "updated"
        await uow.credentials.save(loaded)
        await uow.commit()
        assert loaded.version == 2


@pytest.mark.asyncio
async def test_save_raises_optimistic_lock_conflict(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        await uow.credentials.save(cred)
        await uow.commit()

    async with pg_uow_factory() as uow1:
        c1 = await uow1.credentials.get_by_id(cred.credential_id, tenant_id)
        async with pg_uow_factory() as uow2:
            c2 = await uow2.credentials.get_by_id(cred.credential_id, tenant_id)
            c2.description = "first writer"
            await uow2.credentials.save(c2)
            await uow2.commit()
        c1.description = "second writer"
        with pytest.raises(OptimisticLockConflict):
            await uow1.credentials.save(c1)
        await uow1.rollback()


@pytest.mark.asyncio
async def test_get_by_id_wrong_tenant_raises_not_found(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    other = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        await uow.credentials.save(cred)
        await uow.commit()

    async with pg_uow_factory() as uow:
        with pytest.raises(CredentialNotFound):
            await uow.credentials.get_by_id(cred.credential_id, other)
        await uow.rollback()


@pytest.mark.asyncio
async def test_exists_by_name_true_and_false(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    name = CredentialName(f"exists-{uuid4().hex[:8]}")
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        assert await uow.credentials.exists_by_name(name, tenant_id) is False
        cred = make_credential(tenant_id, backend.backend_id, now, name=name.value)
        await uow.credentials.save(cred)
        await uow.commit()

    async with pg_uow_factory() as uow:
        assert await uow.credentials.exists_by_name(name, tenant_id) is True
        assert (
            await uow.credentials.exists_by_name(CredentialName("definitely-missing"), tenant_id)
            is False
        )
        await uow.rollback()


@pytest.mark.asyncio
async def test_list_by_tenant_with_state_filter(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        active = make_credential(tenant_id, backend.backend_id, now, name="active-cred")
        disabled = make_credential(
            tenant_id,
            backend.backend_id,
            now,
            name="disabled-cred",
            state=CredentialState.DISABLED,
        )
        revoked = make_credential(
            tenant_id,
            backend.backend_id,
            now,
            name="revoked-cred",
            state=CredentialState.REVOKED,
        )
        await uow.credentials.save(active)
        await uow.credentials.save(disabled)
        await uow.credentials.save(revoked)
        await uow.commit()

    async with pg_uow_factory() as uow:
        active_only = await uow.credentials.list_by_tenant(
            tenant_id, states=[CredentialState.ACTIVE]
        )
        assert {item.name.value for item in active_only} == {"active-cred"}
        disabled_only = await uow.credentials.list_by_tenant(
            tenant_id, states=[CredentialState.DISABLED, CredentialState.REVOKED]
        )
        assert {item.name.value for item in disabled_only} == {"disabled-cred", "revoked-cred"}
        await uow.rollback()


@pytest.mark.asyncio
async def test_list_by_tenant_pagination(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        for index in range(5):
            cred = make_credential(tenant_id, backend.backend_id, now, name=f"page-cred-{index}")
            await uow.credentials.save(cred)
        await uow.commit()

    async with pg_uow_factory() as uow:
        page1 = await uow.credentials.list_by_tenant(tenant_id, limit=2, offset=0)
        page2 = await uow.credentials.list_by_tenant(tenant_id, limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert {item.credential_id for item in page1}.isdisjoint(
            {item.credential_id for item in page2}
        )
        await uow.rollback()


@pytest.mark.asyncio
async def test_list_with_rotation_policy_returns_correct_ids(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        policy = await register_rotation_policy(uow, tenant_id, now)
        attached = make_credential(
            tenant_id,
            backend.backend_id,
            now,
            name="with-policy",
            rotation_policy_id=policy.policy_id,
        )
        unattached = make_credential(tenant_id, backend.backend_id, now, name="without-policy")
        await uow.credentials.save(attached)
        await uow.credentials.save(unattached)
        await uow.commit()

    async with pg_uow_factory() as uow:
        ids = await uow.credentials.list_with_rotation_policy(policy.policy_id, tenant_id)
        assert ids == [attached.credential_id]
        await uow.rollback()


@pytest.mark.asyncio
async def test_unique_name_per_tenant_allows_same_name_different_tenants(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_a = TenantId(uuid7())
    tenant_b = TenantId(uuid7())
    shared_name = f"shared-{uuid4().hex[:8]}"
    async with pg_uow_factory() as uow:
        backend_a = await register_backend(uow, tenant_a, now)
        backend_b = await register_backend(uow, tenant_b, now)
        cred_a = make_credential(tenant_a, backend_a.backend_id, now, name=shared_name)
        cred_b = make_credential(tenant_b, backend_b.backend_id, now, name=shared_name)
        await uow.credentials.save(cred_a)
        await uow.credentials.save(cred_b)
        await uow.commit()

    async with pg_uow_factory() as uow:
        loaded_a = await uow.credentials.get_by_name(CredentialName(shared_name), tenant_a)
        loaded_b = await uow.credentials.get_by_name(CredentialName(shared_name), tenant_b)
        assert loaded_a.credential_id == cred_a.credential_id
        assert loaded_b.credential_id == cred_b.credential_id
        await uow.rollback()
