"""Integration tests for SqlAlchemyUnitOfWork (real PostgreSQL)."""

from __future__ import annotations

import pytest

from ioc_intelligence.infrastructure.persistence.repositories.pg_ioc_repository import (
    PgIocRepository,
)
from tests.ioc_intelligence.infrastructure.helpers import make_ioc

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_uow_commit_persists_across_new_session(ioc_uow_factory) -> None:
    ioc = make_ioc(tenant_id=None)
    async with ioc_uow_factory() as uow:
        assert isinstance(uow.iocs, PgIocRepository)
        await uow.iocs.save(ioc)
        await uow.commit()

    async with ioc_uow_factory() as uow:
        fetched = await uow.iocs.get(None, ioc.ioc_id)
        assert fetched is not None


@pytest.mark.asyncio
async def test_uow_uncommitted_work_is_rolled_back_on_exit(ioc_uow_factory) -> None:
    ioc = make_ioc(tenant_id=None)
    async with ioc_uow_factory() as uow:
        await uow.iocs.save(ioc)
        # No explicit commit() — __aexit__ must roll back.

    async with ioc_uow_factory() as uow:
        fetched = await uow.iocs.get(None, ioc.ioc_id)
        assert fetched is None


@pytest.mark.asyncio
async def test_uow_rolls_back_when_body_raises(ioc_uow_factory) -> None:
    ioc = make_ioc(tenant_id=None)
    with pytest.raises(RuntimeError):
        async with ioc_uow_factory() as uow:
            await uow.iocs.save(ioc)
            raise RuntimeError("simulated application error")

    async with ioc_uow_factory() as uow:
        fetched = await uow.iocs.get(None, ioc.ioc_id)
        assert fetched is None
