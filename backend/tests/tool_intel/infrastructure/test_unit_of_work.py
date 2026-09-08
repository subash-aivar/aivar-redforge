from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from tests.tool_intel.infrastructure.helpers import make_tenant_id, make_tool
from tool_intel.infrastructure.persistence.repositories.pg_tool_repository import (
    PgToolRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from tool_intel.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]


async def test_uow_exposes_a_real_repository(
    ti_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    async with ti_uow_factory() as uow:
        assert isinstance(uow.tools, PgToolRepository)


async def test_commit_persists_across_units_of_work(
    ti_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    tool = make_tool(tenant_id=tenant)
    async with ti_uow_factory() as uow:
        await uow.tools.save(tool)
        await uow.commit()

    async with ti_uow_factory() as uow:
        assert await uow.tools.get(tenant, tool.tool_id) is not None


async def test_without_commit_nothing_persists(
    ti_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    tool = make_tool(tenant_id=tenant)
    async with ti_uow_factory() as uow:
        await uow.tools.save(tool)

    async with ti_uow_factory() as uow:
        assert await uow.tools.get(tenant, tool.tool_id) is None


async def test_exception_inside_the_block_rolls_back(
    ti_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    tool = make_tool(tenant_id=tenant)
    with pytest.raises(RuntimeError, match="boom"):
        async with ti_uow_factory() as uow:
            await uow.tools.save(tool)
            raise RuntimeError("boom")

    async with ti_uow_factory() as uow:
        assert await uow.tools.get(tenant, tool.tool_id) is None
