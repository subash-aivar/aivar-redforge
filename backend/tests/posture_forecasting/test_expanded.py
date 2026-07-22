from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from posture_forecasting.api.dependencies import get_container
from posture_forecasting.api.v1 import router
from posture_forecasting.domain.aggregates.forecast_configuration import ForecastConfiguration
from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.services.forecast_accuracy_service import ForecastAccuracyService
from posture_forecasting.domain.services.forecast_generation_service import (
    ForecastGenerationService,
)
from posture_forecasting.domain.value_objects.identifiers import TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload,
    M32ExposureTranslator,
)
from posture_forecasting.infrastructure.container import PostureForecastingContainer
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission


def _snap(tenant: TenantId, baseline: float = 80.0, velocity: float = 1.0) -> ForecastInputSnapshot:
    return ForecastInputSnapshot(
        baseline_exposure_score=baseline,
        remediation_velocity_per_day=velocity,
        open_critical_count=2,
        open_high_count=3,
        snapshot_at=datetime.now(UTC),
        tenant_id=tenant,
    )


@pytest.mark.parametrize("baseline", [0, 10, 25, 40, 55, 70, 85, 100])
def test_generate_baselines(baseline: float) -> None:
    tenant = TenantId(uuid4())
    f = ForecastGenerationService().generate(tenant, _snap(tenant, baseline=baseline))
    assert f.predicted_90d <= f.predicted_30d


@pytest.mark.parametrize("velocity", [0.0, 0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0])
def test_generate_velocities(velocity: float) -> None:
    tenant = TenantId(uuid4())
    f = ForecastGenerationService().generate(tenant, _snap(tenant, velocity=velocity))
    assert f.input_snapshot is not None


@pytest.mark.parametrize("horizon", [30, 60, 90])
@pytest.mark.parametrize("actual", [10.0, 20.0, 30.0, 40.0, 50.0])
def test_accuracy_matrix(horizon: int, actual: float) -> None:
    tenant = TenantId(uuid4())
    f = PostureForecast.create(tenant, _snap(tenant), 40, 30, 20, "m", 1)
    ForecastAccuracyService().record(f, horizon, actual)
    assert f.accuracy_records[-1].horizon_days == horizon


@pytest.mark.parametrize("score", [5.0, 15.0, 35.0, 55.0, 75.0, 95.0])
def test_acl_matrix(score: float) -> None:
    assert (
        M32ExposureTranslator().translate(ExposureScoreUpdatedPayload("t", score, 1, 1, 1.0))
        is not None
    )


def test_config_default() -> None:
    cfg = ForecastConfiguration.default(TenantId(uuid4()))
    assert cfg.forecast_frequency_hours == 24


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(5))
async def test_worker_ticks(i: int) -> None:
    c = PostureForecastingContainer()
    result = await c.scheduler.tick_all(uuid4())
    assert result["forecast_runs"] >= 1


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    return TenantContext(
        user_id=str(uuid4()),
        email="posture-forecasting-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    c = PostureForecastingContainer()
    app.dependency_overrides[get_container] = lambda: c
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    return TestClient(app)


@pytest.mark.parametrize("baseline", [10.0, 30.0, 50.0, 70.0, 90.0])
def test_api_generate(client: TestClient, baseline: float) -> None:
    r = client.post(
        "/posture-forecasting/forecasts",
        headers={"X-Tenant-Id": str(uuid4()), "X-Roles": "system,ai:operator"},
        json={"baseline_exposure_score": baseline},
    )
    assert r.status_code == 201


@pytest.mark.parametrize("i", range(5))
def test_api_health(client: TestClient, i: int) -> None:
    assert client.get("/posture-forecasting/health").status_code == 200
