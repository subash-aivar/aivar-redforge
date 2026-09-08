from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from campaign_intel.infrastructure.persistence.repositories.pg_campaign_repository import (
    PgCampaignRepository,
)
from tests.campaign_intel.infrastructure.helpers import make_campaign, make_tenant_id

if TYPE_CHECKING:
    from collections.abc import Callable

    from campaign_intel.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]


async def test_uow_exposes_a_real_repository(
    cp_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    async with cp_uow_factory() as uow:
        assert isinstance(uow.campaigns, PgCampaignRepository)


async def test_commit_persists_across_units_of_work(
    cp_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    campaign = make_campaign(tenant_id=tenant)
    async with cp_uow_factory() as uow:
        await uow.campaigns.save(campaign)
        await uow.commit()

    async with cp_uow_factory() as uow:
        assert await uow.campaigns.get(tenant, campaign.campaign_id) is not None


async def test_without_commit_nothing_persists(
    cp_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    campaign = make_campaign(tenant_id=tenant)
    async with cp_uow_factory() as uow:
        await uow.campaigns.save(campaign)

    async with cp_uow_factory() as uow:
        assert await uow.campaigns.get(tenant, campaign.campaign_id) is None


async def test_exception_inside_the_block_rolls_back(
    cp_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    campaign = make_campaign(tenant_id=tenant)
    with pytest.raises(RuntimeError, match="boom"):
        async with cp_uow_factory() as uow:
            await uow.campaigns.save(campaign)
            raise RuntimeError("boom")

    async with cp_uow_factory() as uow:
        assert await uow.campaigns.get(tenant, campaign.campaign_id) is None
