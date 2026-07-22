"""Integration tests for analytics's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from analytics.domain.aggregates.analytics_dataset import AnalyticsDataSet
from analytics.domain.aggregates.analytics_query import AnalyticsQuery
from analytics.domain.aggregates.anomaly_detection_baseline import AnomalyDetectionBaseline
from analytics.domain.aggregates.security_kpi import SecurityKPI
from analytics.domain.value_objects.enums import (
    AnomalySignalType,
    DetectionMethod,
    KPIType,
    SecurityDomain,
)
from analytics.domain.value_objects.identifiers import (
    AnalyticsDataSetId,
    AnalyticsQueryId,
    AnomalyDetectionBaselineId,
    SecurityKPIId,
    TenantId,
)
from analytics.infrastructure.persistence.postgres_repositories import (
    PgAnalyticsDataSetRepository,
    PgAnalyticsQueryRepository,
    PgAnomalyDetectionBaselineRepository,
    PgSecurityKPIRepository,
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
async def test_dataset_lifecycle(session_factory) -> None:
    repo = PgAnalyticsDataSetRepository(session_factory)
    tenant_id = TenantId(uuid7())
    now = datetime.now(UTC)

    ds = AnalyticsDataSet.register(
        AnalyticsDataSetId.generate(), tenant_id, SecurityDomain.DETECTION, "v1", now
    )
    ds.advance_checkpoint(tenant_id, "evt-1", now, ingested=5)
    await repo.save(tenant_id, ds)

    fetched = await repo.find_by_id(tenant_id, ds.dataset_id)
    assert fetched is not None
    assert fetched.records_ingested == 5
    assert fetched.projection_checkpoint == "evt-1"

    by_domain = await repo.find_by_domain(tenant_id, SecurityDomain.DETECTION)
    assert len(by_domain) == 1

    active = await repo.find_all_active(tenant_id)
    assert len(active) == 1

    fetched.begin_rebuild(tenant_id, now)
    await repo.save(tenant_id, fetched)

    active_after = await repo.find_all_active(tenant_id)
    assert active_after == []


@pytest.mark.asyncio
async def test_kpi_upsert_by_type(session_factory) -> None:
    repo = PgSecurityKPIRepository(session_factory)
    tenant_id = TenantId(uuid7())
    now = datetime.now(UTC)

    kpi = SecurityKPI.define(SecurityKPIId.generate(), tenant_id, KPIType.MTTD, "0 * * * *", now)
    await repo.save(tenant_id, kpi)

    kpi.record_computation(tenant_id, value=42.5, unit="minutes", status=kpi.status, at=now)
    await repo.save(tenant_id, kpi)

    fetched = await repo.find_by_type(tenant_id, KPIType.MTTD)
    assert fetched is not None
    assert fetched.latest_value == 42.5
    assert fetched.latest_unit == "minutes"

    due = await repo.find_due_for_computation(now)
    assert any(str(k.kpi_id) == str(kpi.kpi_id) for k in due)


@pytest.mark.asyncio
async def test_anomaly_baseline_bootstrap_round_trip(session_factory) -> None:
    repo = PgAnomalyDetectionBaselineRepository(session_factory)
    tenant_id = TenantId(uuid7())
    now = datetime.now(UTC)

    baseline = AnomalyDetectionBaseline.create(
        AnomalyDetectionBaselineId.generate(),
        tenant_id,
        AnomalySignalType.DETECTION_FP_RATE,
        DetectionMethod.ZSCORE,
        30,
        now,
    )
    baseline.bootstrap(tenant_id, values=[float(i) for i in range(20)], at=now)
    await repo.save(tenant_id, baseline)

    fetched = await repo.find_by_signal_type(tenant_id, AnomalySignalType.DETECTION_FP_RATE)
    assert fetched is not None
    assert fetched.bootstrapped is True
    assert fetched.observation_count == 20
    assert fetched.mean == pytest.approx(9.5)


@pytest.mark.asyncio
async def test_analytics_query_save_and_find(session_factory) -> None:
    repo = PgAnalyticsQueryRepository(session_factory)
    tenant_id = TenantId(uuid7())
    now = datetime.now(UTC)

    query = AnalyticsQuery.create(
        AnalyticsQueryId.generate(),
        tenant_id,
        "Top detections by FP rate",
        "SELECT * FROM detections WHERE fp_rate > :threshold",
        SecurityDomain.DETECTION,
        ["threshold"],
        "analyst-1",
        now,
    )
    await repo.save(tenant_id, query)

    fetched = await repo.find_by_id(tenant_id, query.query_id)
    assert fetched is not None
    assert fetched.parameter_names == ["threshold"]

    all_queries = await repo.find_all(tenant_id)
    assert len(all_queries) == 1
