from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from tests.threat_report_intel.infrastructure.helpers import make_tenant_id, make_threat_report
from threat_report_intel.infrastructure.persistence.repositories.pg_threat_report_repository import (
    PgThreatReportRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from threat_report_intel.infrastructure.persistence.unit_of_work import (
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
    tr_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    async with tr_uow_factory() as uow:
        assert isinstance(uow.threat_reports, PgThreatReportRepository)


async def test_commit_persists_across_units_of_work(
    tr_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    record = make_threat_report(tenant_id=tenant)
    async with tr_uow_factory() as uow:
        await uow.threat_reports.save(record)
        await uow.commit()

    async with tr_uow_factory() as uow:
        assert await uow.threat_reports.get(tenant, record.threat_report_id) is not None


async def test_without_commit_nothing_persists(
    tr_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    record = make_threat_report(tenant_id=tenant)
    async with tr_uow_factory() as uow:
        await uow.threat_reports.save(record)

    async with tr_uow_factory() as uow:
        assert await uow.threat_reports.get(tenant, record.threat_report_id) is None


async def test_exception_inside_the_block_rolls_back(
    tr_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant = make_tenant_id()
    record = make_threat_report(tenant_id=tenant)
    with pytest.raises(RuntimeError, match="boom"):
        async with tr_uow_factory() as uow:
            await uow.threat_reports.save(record)
            raise RuntimeError("boom")

    async with tr_uow_factory() as uow:
        assert await uow.threat_reports.get(tenant, record.threat_report_id) is None
