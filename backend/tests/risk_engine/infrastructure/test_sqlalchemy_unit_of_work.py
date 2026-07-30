"""Integration tests for SqlAlchemyUnitOfWork transaction boundaries."""

from __future__ import annotations

import pytest

from tests.risk_engine.infrastructure.helpers import (
    make_correlation_set,
    make_profile,
    make_tenant_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_commit_persists_across_new_sessions(re_uow_factory) -> None:
    tenant_id = make_tenant_id()
    profile = make_profile(tenant_id, subject_reference="uow-commit")

    async with re_uow_factory() as uow:
        await uow.risk_profiles.save(profile)
        await uow.commit()

    async with re_uow_factory() as uow:
        loaded = await uow.risk_profiles.get(tenant_id, profile.profile_id)
        assert loaded is not None
        assert loaded.subject_reference == "uow-commit"
        await uow.rollback()


@pytest.mark.asyncio
async def test_uncommitted_changes_are_rolled_back_on_context_exit(re_uow_factory) -> None:
    tenant_id = make_tenant_id()
    profile = make_profile(tenant_id, subject_reference="uow-no-commit")

    async with re_uow_factory() as uow:
        await uow.risk_profiles.save(profile)
        # intentionally never call commit()

    async with re_uow_factory() as uow:
        loaded = await uow.risk_profiles.get(tenant_id, profile.profile_id)
        assert loaded is None
        await uow.rollback()


@pytest.mark.asyncio
async def test_exception_inside_uow_rolls_back(re_uow_factory) -> None:
    tenant_id = make_tenant_id()
    profile = make_profile(tenant_id, subject_reference="uow-exception")

    with pytest.raises(RuntimeError):
        async with re_uow_factory() as uow:
            await uow.risk_profiles.save(profile)
            raise RuntimeError("boom")

    async with re_uow_factory() as uow:
        loaded = await uow.risk_profiles.get(tenant_id, profile.profile_id)
        assert loaded is None
        await uow.rollback()


@pytest.mark.asyncio
async def test_uow_bundles_both_repositories(re_uow_factory) -> None:
    tenant_id = make_tenant_id()
    profile = make_profile(tenant_id)
    correlation_set = make_correlation_set(tenant_id)

    async with re_uow_factory() as uow:
        await uow.risk_profiles.save(profile)
        await uow.correlation_sets.save(correlation_set)
        await uow.commit()

    async with re_uow_factory() as uow:
        assert await uow.risk_profiles.get(tenant_id, profile.profile_id) is not None
        assert (
            await uow.correlation_sets.get(tenant_id, correlation_set.correlation_set_id)
            is not None
        )
        await uow.rollback()
