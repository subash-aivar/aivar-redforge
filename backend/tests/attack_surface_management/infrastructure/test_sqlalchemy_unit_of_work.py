"""Integration tests for SqlAlchemyUnitOfWork transaction boundaries."""

from __future__ import annotations

import pytest

from tests.attack_surface_management.infrastructure.helpers import (
    make_asset,
    make_network_range,
    make_tenant_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_commit_persists_across_new_sessions(asm_uow_factory) -> None:
    tenant_id = make_tenant_id()
    asset = make_asset(tenant_id, domain="uow-commit.example.com")

    async with asm_uow_factory() as uow:
        await uow.assets.save(asset)
        await uow.commit()

    async with asm_uow_factory() as uow:
        loaded = await uow.assets.get(tenant_id, asset.asset_id)
        assert loaded is not None
        assert loaded.domain_name is not None
        assert str(loaded.domain_name) == "uow-commit.example.com"
        await uow.rollback()


@pytest.mark.asyncio
async def test_uncommitted_changes_are_rolled_back_on_context_exit(asm_uow_factory) -> None:
    tenant_id = make_tenant_id()
    asset = make_asset(tenant_id, domain="uow-no-commit.example.com")

    async with asm_uow_factory() as uow:
        await uow.assets.save(asset)
        # intentionally never call commit()

    async with asm_uow_factory() as uow:
        loaded = await uow.assets.get(tenant_id, asset.asset_id)
        assert loaded is None
        await uow.rollback()


@pytest.mark.asyncio
async def test_exception_inside_uow_rolls_back(asm_uow_factory) -> None:
    tenant_id = make_tenant_id()
    asset = make_asset(tenant_id, domain="uow-exception.example.com")

    with pytest.raises(RuntimeError):
        async with asm_uow_factory() as uow:
            await uow.assets.save(asset)
            raise RuntimeError("boom")

    async with asm_uow_factory() as uow:
        loaded = await uow.assets.get(tenant_id, asset.asset_id)
        assert loaded is None
        await uow.rollback()


@pytest.mark.asyncio
async def test_uow_bundles_both_repositories(asm_uow_factory) -> None:
    tenant_id = make_tenant_id()
    asset = make_asset(tenant_id)
    network_range = make_network_range(tenant_id)

    async with asm_uow_factory() as uow:
        await uow.assets.save(asset)
        await uow.network_ranges.save(network_range)
        await uow.commit()

    async with asm_uow_factory() as uow:
        assert await uow.assets.get(tenant_id, asset.asset_id) is not None
        assert await uow.network_ranges.get(tenant_id, network_range.range_id) is not None
        await uow.rollback()
