"""Accuracy gate FAIL → MLModel status FAILED."""

from __future__ import annotations

import pytest

from ml_pipeline.application.commands.ml_commands import ScheduleMLModelTrainingCommand
from ml_pipeline.domain.value_objects.enums import MLModelStatus, MLModelType
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.mark.asyncio
async def test_accuracy_gate_fail_random_forest(
    container: MLPipelineContainer, tenant_id, admin_roles
) -> None:
    # Constant features + alternating labels → AUC-ROC ~0.5 << 0.70
    rows = tuple(
        {
            "exposure_score": 1.0,
            "vuln_count": 1.0,
            "detection_gap": 1.0,
            "ai_risk": 1.0,
            "label": i % 2,
        }
        for i in range(60)
    )

    result = await container.app.schedule_training(
        ScheduleMLModelTrainingCommand(
            tenant_id,
            MLModelType.RISK_PREDICTOR.value,
            None,
            admin_roles,
            rows,
        )
    )
    assert result["status"] == MLModelStatus.FAILED.value
    assert result["failure_reason"]
    assert (
        "Accuracy gate failed" in result["failure_reason"]
        or "below" in (result["failure_reason"] or "").lower()
        or "INSUFFICIENT" in (result["failure_reason"] or "")
    )
