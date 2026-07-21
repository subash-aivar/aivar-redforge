"""Inference pipeline + advisory-only security graph write."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ml_pipeline.application.commands.ml_commands import (
    PromoteMLModelCommand,
    ScheduleMLModelTrainingCommand,
)
from ml_pipeline.domain.value_objects.enums import MLModelType
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.mark.asyncio
async def test_inference_and_graph_write(
    container: MLPipelineContainer, tenant_id, admin_roles
) -> None:
    trained = await container.app.schedule_training(
        ScheduleMLModelTrainingCommand(
            tenant_id, MLModelType.RISK_PREDICTOR.value, None, admin_roles
        )
    )
    mid = UUID(trained["model_id"])
    await container.app.promote(PromoteMLModelCommand(tenant_id, mid, "admin", admin_roles))
    assets = [
        {
            "asset_ref_id": str(uuid4()),
            "exposure_score": 8.0,
            "vuln_count": 5.0,
            "detection_gap": 4.0,
            "ai_risk": 6.0,
        },
        {
            "asset_ref_id": str(uuid4()),
            "exposure_score": 1.0,
            "vuln_count": 0.5,
            "detection_gap": 0.2,
            "ai_risk": 0.3,
        },
    ]
    result = await container.app.run_inference(
        tenant_id, MLModelType.RISK_PREDICTOR.value, assets, admin_roles
    )
    assert result["status"] == "OK"
    assert result["count"] == 2
    assert len(container.graph.nodes) == 2
    for node in container.graph.nodes:
        assert node["kind"] == "predictive_risk"
        assert node["advisory_only"] is True
        assert "score" in node
