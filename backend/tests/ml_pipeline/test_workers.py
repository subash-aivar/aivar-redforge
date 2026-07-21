"""Workers: MLTrainingWorker, MLInferenceWorker, DriftCheckWorker."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ml_pipeline.application.commands.ml_commands import PromoteMLModelCommand
from ml_pipeline.domain.value_objects.enums import MLModelType
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.mark.asyncio
async def test_training_worker_dedup(container: MLPipelineContainer, tenant_id) -> None:
    r1 = await container.training_worker.run(
        job_id="job-1",
        tenant_id=tenant_id,
        model_type=MLModelType.RISK_PREDICTOR.value,
    )
    r2 = await container.training_worker.run(
        job_id="job-1",
        tenant_id=tenant_id,
        model_type=MLModelType.RISK_PREDICTOR.value,
    )
    assert r1["deduplicated"] is False
    assert r2["deduplicated"] is True
    assert r1["status"] == "TRAINED"


@pytest.mark.asyncio
async def test_inference_worker(container: MLPipelineContainer, tenant_id, admin_roles) -> None:
    trained = await container.training_worker.run(
        job_id="job-inf",
        tenant_id=tenant_id,
        model_type=MLModelType.RISK_PREDICTOR.value,
    )
    await container.app.promote(
        PromoteMLModelCommand(tenant_id, UUID(trained["model_id"]), "admin", admin_roles)
    )
    result = await container.inference_worker.run(
        tenant_id=tenant_id,
        model_type=MLModelType.RISK_PREDICTOR.value,
        assets=[
            {
                "asset_ref_id": str(uuid4()),
                "exposure_score": 3.0,
                "vuln_count": 1.0,
                "detection_gap": 1.0,
                "ai_risk": 1.0,
            }
        ],
    )
    assert result["status"] == "OK"
