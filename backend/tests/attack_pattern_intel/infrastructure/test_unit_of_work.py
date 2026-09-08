"""Integration tests for SqlAlchemyUnitOfWork (real PostgreSQL)."""

from __future__ import annotations

import pytest

from attack_pattern_intel.infrastructure.persistence.repositories.pg_attack_pattern_repository import (
    PgAttackPatternRepository,
)
from tests.attack_pattern_intel.infrastructure.helpers import make_pattern

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_uow_commit_persists_across_new_session(ap_uow_factory) -> None:
    pattern = make_pattern(tenant_id=None)
    async with ap_uow_factory() as uow:
        assert isinstance(uow.attack_patterns, PgAttackPatternRepository)
        await uow.attack_patterns.save(pattern)
        await uow.commit()

    async with ap_uow_factory() as uow:
        fetched = await uow.attack_patterns.get(None, pattern.attack_pattern_id)
        assert fetched is not None


@pytest.mark.asyncio
async def test_uow_uncommitted_work_is_rolled_back_on_exit(ap_uow_factory) -> None:
    pattern = make_pattern(tenant_id=None)
    async with ap_uow_factory() as uow:
        await uow.attack_patterns.save(pattern)
        # No explicit commit() — __aexit__ must roll back.

    async with ap_uow_factory() as uow:
        fetched = await uow.attack_patterns.get(None, pattern.attack_pattern_id)
        assert fetched is None


@pytest.mark.asyncio
async def test_uow_rolls_back_when_body_raises(ap_uow_factory) -> None:
    pattern = make_pattern(tenant_id=None)
    with pytest.raises(RuntimeError):
        async with ap_uow_factory() as uow:
            await uow.attack_patterns.save(pattern)
            raise RuntimeError("simulated application error")

    async with ap_uow_factory() as uow:
        fetched = await uow.attack_patterns.get(None, pattern.attack_pattern_id)
        assert fetched is None
