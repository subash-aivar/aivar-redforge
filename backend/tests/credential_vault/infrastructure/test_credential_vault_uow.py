"""Integration tests for CredentialVaultUnitOfWork."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid7

import pytest
from tests.credential_vault.infrastructure.repository_helpers import (
    make_credential,
    register_backend,
)

from credential_vault.domain.exceptions.domain_exceptions import CredentialNotFound
from credential_vault.domain.value_objects.identifiers import TenantId

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_commit_persists_data(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    async with pg_uow_factory() as uow:
        backend = await register_backend(uow, tenant_id, now)
        cred = make_credential(tenant_id, backend.backend_id, now)
        await uow.credentials.save(cred)
        await uow.commit()

    async with pg_uow_factory() as uow:
        loaded = await uow.credentials.get_by_id(cred.credential_id, tenant_id)
        assert loaded.name.value == cred.name.value
        await uow.rollback()


@pytest.mark.asyncio
async def test_exception_causes_rollback(pg_uow_factory) -> None:
    now = datetime.now(UTC)
    tenant_id = TenantId(uuid7())
    cred_id = None
    try:
        async with pg_uow_factory() as uow:
            backend = await register_backend(uow, tenant_id, now)
            cred = make_credential(tenant_id, backend.backend_id, now)
            cred_id = cred.credential_id
            await uow.credentials.save(cred)
            raise RuntimeError("force rollback")
    except RuntimeError:
        pass

    assert cred_id is not None
    async with pg_uow_factory() as uow:
        with pytest.raises(CredentialNotFound):
            await uow.credentials.get_by_id(cred_id, tenant_id)
        await uow.rollback()


@pytest.mark.asyncio
async def test_all_six_repos_accessible(pg_uow) -> None:
    assert pg_uow.credentials is not None
    assert pg_uow.versions is not None
    assert pg_uow.rotation_policies is not None
    assert pg_uow.expiration_policies is not None
    assert pg_uow.vault_backends is not None
    assert pg_uow.audit_logs is not None


@pytest.mark.asyncio
async def test_session_closed_after_exit(pg_uow_factory) -> None:
    session = None
    async with pg_uow_factory() as uow:
        session = uow._session
        assert session is not None

    assert session is not None
    assert uow._session is None
