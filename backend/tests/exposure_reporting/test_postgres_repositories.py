"""Integration tests for exposure_reporting's Postgres repositories and stores."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from exposure_reporting.domain.aggregates.business_impact_mapping import BusinessImpactMapping
from exposure_reporting.domain.aggregates.exposure_report import ExposureReport
from exposure_reporting.domain.value_objects.enums import (
    BusinessCriticality,
    ImpactDomain,
    ReportType,
)
from exposure_reporting.domain.value_objects.identifiers import (
    BusinessImpactMappingId,
    ExposureReportId,
    TenantId,
)
from exposure_reporting.infrastructure.persistence.postgres_projection_stores import (
    PgKpiProjectionStore,
    PgTrendProjectionStore,
)
from exposure_reporting.infrastructure.persistence.postgres_repositories import (
    PgBusinessImpactMappingRepository,
    PgExposureReportRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_report_save_get_list_and_deliver(session_factory) -> None:
    repo = PgExposureReportRepository(session_factory)
    tenant_id = TenantId(uuid7())

    report = ExposureReport.create(
        ExposureReportId.generate(),
        tenant_id,
        ReportType.BOARD_RISK_SUMMARY,
        "template-1",
        "Exposure narrative",
        {"top_risks": ["CVE-2026-1"]},
        "analyst-1",
        datetime.now(UTC),
    )
    await repo.save(tenant_id, report)

    fetched = await repo.get(tenant_id, report.report_id)
    assert fetched is not None
    assert fetched.narrative == "Exposure narrative"
    assert fetched.content == {"top_risks": ["CVE-2026-1"]}

    report.mark_delivered(tenant_id, "email", datetime.now(UTC))
    await repo.save(tenant_id, report)

    delivered = await repo.get(tenant_id, report.report_id)
    assert delivered is not None
    assert delivered.status.value == "Delivered"

    listed = await repo.list_by_tenant(tenant_id, report_type="BoardRiskSummary")
    assert any(str(r.report_id) == str(report.report_id) for r in listed)


@pytest.mark.asyncio
async def test_business_impact_mapping_round_trip_and_find_by_asset(session_factory) -> None:
    repo = PgBusinessImpactMappingRepository(session_factory)
    tenant_id = TenantId(uuid7())
    asset_ref_id = uuid7()

    mapping = BusinessImpactMapping.create(
        BusinessImpactMappingId.generate(),
        tenant_id,
        asset_ref_id,
        BusinessCriticality.MISSION_CRITICAL,
        ImpactDomain.REVENUE,
        "author-1",
        datetime.now(UTC),
        financial_impact_estimate=250000.0,
        regulatory_scope=["PCI-DSS"],
    )
    await repo.save(tenant_id, mapping)

    fetched = await repo.find_by_asset(tenant_id, asset_ref_id)
    assert fetched is not None
    assert fetched.criticality == BusinessCriticality.MISSION_CRITICAL
    assert fetched.regulatory_scope == ["PCI-DSS"]

    listed = await repo.list_by_tenant(tenant_id)
    assert len(listed) == 1


@pytest.mark.asyncio
async def test_kpi_projection_store_upsert_get_clear(session_factory) -> None:
    store = PgKpiProjectionStore(session_factory)
    tenant_id = uuid7()

    assert await store.get(tenant_id) is None

    await store.upsert(tenant_id, {"critical_count": 3}, datetime.now(UTC))
    kpi = await store.get(tenant_id)
    assert kpi is not None
    assert kpi["critical_count"] == 3

    await store.upsert(tenant_id, {"critical_count": 5}, datetime.now(UTC))
    kpi2 = await store.get(tenant_id)
    assert kpi2 is not None
    assert kpi2["critical_count"] == 5

    await store.clear(tenant_id)
    assert await store.get(tenant_id) is None


@pytest.mark.asyncio
async def test_trend_projection_store_append_list_clear(session_factory) -> None:
    store = PgTrendProjectionStore(session_factory)
    tenant_id = uuid7()

    await store.append(
        tenant_id,
        tenant_exposure_score=42.0,
        asset_count=10,
        at=datetime.now(UTC),
        score_input_version="v1",
    )
    await store.append(
        tenant_id,
        tenant_exposure_score=38.0,
        asset_count=12,
        at=datetime.now(UTC),
        score_input_version="v2",
    )

    points = await store.list_points(tenant_id)
    assert len(points) == 2
    assert points[0].score_input_version == "v1"

    await store.clear(tenant_id)
    assert await store.list_points(tenant_id) == []
