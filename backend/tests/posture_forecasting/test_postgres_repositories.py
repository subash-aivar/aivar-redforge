"""Integration tests for posture_forecasting's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.value_objects.identifiers import ForecastId, TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot
from posture_forecasting.infrastructure.persistence.postgres_repositories import (
    PgForecastConfigurationRepository,
    PgPostureForecastRepository,
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
async def test_save_and_find_latest_round_trip(session_factory) -> None:
    repo = PgPostureForecastRepository(session_factory)
    tenant_id = TenantId(uuid7())
    now = datetime.now(UTC)

    snapshot = ForecastInputSnapshot(
        baseline_exposure_score=52.0,
        remediation_velocity_per_day=1.2,
        open_critical_count=3,
        open_high_count=8,
        snapshot_at=now,
        tenant_id=tenant_id,
    )
    forecast = PostureForecast.create(tenant_id, snapshot, 48.0, 44.0, 40.0, "model-x", 2)
    await repo.save(forecast, tenant_id)

    latest = await repo.find_latest(tenant_id)
    assert latest is not None
    assert latest.model_id == "model-x"
    assert latest.predicted_30d == 48.0
    assert latest.input_snapshot.baseline_exposure_score == 52.0
    assert latest.input_snapshot.open_critical_count == 3
    assert latest.accuracy_records == []


@pytest.mark.asyncio
async def test_accuracy_record_persists_and_removes_pending_status(session_factory) -> None:
    repo = PgPostureForecastRepository(session_factory)
    tenant_id = TenantId(uuid7())
    stale_at = datetime.now(UTC) - timedelta(days=40)

    snapshot = ForecastInputSnapshot(
        baseline_exposure_score=60.0,
        remediation_velocity_per_day=0.8,
        open_critical_count=1,
        open_high_count=2,
        snapshot_at=stale_at,
        tenant_id=tenant_id,
    )
    forecast = PostureForecast(
        forecast_id=ForecastId.generate(),
        tenant_id=tenant_id,
        input_snapshot=snapshot,
        predicted_30d=55.0,
        predicted_60d=50.0,
        predicted_90d=45.0,
        model_id="model-y",
        model_version=1,
        generated_at=stale_at,
    )
    await repo.save(forecast, tenant_id)

    pending = await repo.find_pending_accuracy_check(30, datetime.now(UTC))
    assert any(str(f.forecast_id) == str(forecast.forecast_id) for f in pending)

    forecast.record_accuracy(30, actual_score=53.0, predicted_score=55.0)
    await repo.save(forecast, tenant_id)

    still_pending = await repo.find_pending_accuracy_check(30, datetime.now(UTC))
    assert not any(str(f.forecast_id) == str(forecast.forecast_id) for f in still_pending)

    latest = await repo.find_latest(tenant_id)
    assert latest is not None
    assert len(latest.accuracy_records) == 1
    assert latest.accuracy_records[0].absolute_error == pytest.approx(2.0)


@pytest.mark.asyncio
async def test_configuration_get_or_create_default_is_idempotent(session_factory) -> None:
    repo = PgForecastConfigurationRepository(session_factory)
    tenant_id = TenantId(uuid7())

    first = await repo.get_or_create_default(tenant_id)
    assert first.forecast_frequency_hours == 24
    assert first.signal_weights == {"exposure": 0.6, "remediation_velocity": 0.4}

    second = await repo.get_or_create_default(tenant_id)
    assert second.forecast_frequency_hours == first.forecast_frequency_hours
    assert second.signal_weights == first.signal_weights
