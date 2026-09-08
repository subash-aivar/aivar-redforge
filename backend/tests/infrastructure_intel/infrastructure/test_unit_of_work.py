from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from infrastructure_intel.infrastructure.persistence.repositories.pg_infrastructure_repository import (
    PgInfrastructureRepository,
)
from tests.infrastructure_intel.infrastructure.helpers import (
    make_infrastructure,
    make_tenant_id,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from infrastructure_intel.infrastructure.persistence.unit_of_work import (
        SqlAlchemyUnitOfWork,
    )

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]


async def test_uow_exposes_a_real_repository(
    ii_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    async with ii_uow_factory() as uow:
        assert isinstance(uow.infrastructure, PgInfrastructureRepository)


async def test_commit_persists_across_units_of_work(
    ii_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    record = make_infrastructure(tenant_id=tenant)
    async with ii_uow_factory() as uow:
        await uow.infrastructure.save(record)
        await uow.commit()

    async with ii_uow_factory() as uow:
        assert await uow.infrastructure.get(tenant, record.infrastructure_id) is not None


async def test_without_commit_nothing_persists(
    ii_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    record = make_infrastructure(tenant_id=tenant)
    async with ii_uow_factory() as uow:
        await uow.infrastructure.save(record)

    async with ii_uow_factory() as uow:
        assert await uow.infrastructure.get(tenant, record.infrastructure_id) is None


async def test_exception_inside_the_block_rolls_back(
    ii_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    record = make_infrastructure(tenant_id=tenant)
    with pytest.raises(RuntimeError, match="boom"):
        async with ii_uow_factory() as uow:
            await uow.infrastructure.save(record)
            raise RuntimeError("boom")

    async with ii_uow_factory() as uow:
        assert await uow.infrastructure.get(tenant, record.infrastructure_id) is None
