from __future__ import annotations

from datetime import UTC, datetime

import pytest

from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.services.forecast_generation_service import (
    ForecastGenerationService,
)
from posture_forecasting.domain.value_objects.identifiers import TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload,
    M32ExposureTranslator,
)


@pytest.mark.parametrize("velocity", [0.0, 0.5, 1.0, 2.0, 5.0])
def test_forecast_decreases_with_velocity(velocity: float) -> None:
    tenant = TenantId.generate()
    snap = ForecastInputSnapshot(
        baseline_exposure_score=100.0,
        remediation_velocity_per_day=velocity,
        open_critical_count=1,
        open_high_count=2,
        snapshot_at=datetime.now(UTC),
        tenant_id=tenant,
    )
    f = ForecastGenerationService().generate(tenant, snap)
    assert f.predicted_30d >= f.predicted_90d


@pytest.mark.parametrize("horizon", [30, 60, 90])
def test_accuracy_record(horizon: int) -> None:
    tenant = TenantId.generate()
    snap = ForecastInputSnapshot(
        baseline_exposure_score=50.0,
        remediation_velocity_per_day=1.0,
        open_critical_count=0,
        open_high_count=0,
        snapshot_at=datetime.now(UTC),
        tenant_id=tenant,
    )
    f = PostureForecast.create(tenant, snap, 40, 30, 20, "m", 1)
    f.record_accuracy(horizon, 35.0, {30: 40, 60: 30, 90: 20}[horizon])
    assert f.accuracy_records[-1].horizon_days == horizon


def test_acl_translator() -> None:
    sig = M32ExposureTranslator().translate(ExposureScoreUpdatedPayload("t", 55.0, 1, 2, 1.5))
    assert sig is not None
    assert sig.exposure_score == 55.0
