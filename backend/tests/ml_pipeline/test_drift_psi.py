"""PSI drift detection — auto-deprecate at PSI ≥ 0.20."""

from __future__ import annotations

from uuid import UUID

import numpy as np
import pytest

from ml_pipeline.application.commands.ml_commands import (
    PromoteMLModelCommand,
    ScheduleMLModelTrainingCommand,
)
from ml_pipeline.domain.services.drift_detection_service import DriftDetectionService
from ml_pipeline.domain.value_objects.enums import MLModelStatus, MLModelType
from ml_pipeline.infrastructure.container import MLPipelineContainer


def test_psi_formula_stable_vs_severe() -> None:
    svc = DriftDetectionService()
    rng = np.random.default_rng(0)
    expected = rng.normal(0, 1, 500).tolist()
    stable = svc.compute_psi(expected, expected)
    assert not stable.severe
    shifted = (np.asarray(expected) + 3.0).tolist()
    severe = svc.compute_psi(expected, shifted)
    assert severe.psi >= 0.20
    assert severe.severe


@pytest.mark.asyncio
async def test_psi_auto_deprecate(container: MLPipelineContainer, tenant_id, admin_roles) -> None:
    trained = await container.app.schedule_training(
        ScheduleMLModelTrainingCommand(
            tenant_id, MLModelType.RISK_PREDICTOR.value, None, admin_roles
        )
    )
    mid = UUID(trained["model_id"])
    await container.app.promote(PromoteMLModelCommand(tenant_id, mid, "admin", admin_roles))
    baseline = container.app._baselines[str(mid)]
    # Strong shift to force PSI ≥ 0.20
    actual = [v + 50.0 for v in baseline]
    result = await container.app.check_drift(tenant_id, mid, actual)
    assert result["severe"] is True
    assert result["status"] == MLModelStatus.DEPRECATED.value
