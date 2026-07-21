from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ml_pipeline.application.commands.ml_commands import (
    PromoteMLModelCommand,
    ScheduleMLModelTrainingCommand,
)
from ml_pipeline.application.exceptions import ApplicationForbiddenError
from ml_pipeline.domain.exceptions.domain_exceptions import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
)
from ml_pipeline.domain.services.drift_detection_service import DriftDetectionService
from ml_pipeline.domain.services.ml_inference_service import MLInferenceService
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.mark.asyncio
async def test_train_promote_infer_isolation_forest() -> None:
    c = MLPipelineContainer()
    tid = uuid4()
    trained = await c.app.schedule_training(
        ScheduleMLModelTrainingCommand(tid, "ANOMALY_DETECTOR", None, ("analytics:admin",), ())
    )
    assert trained["status"] == "TRAINED"
    mid = UUID(trained["model_id"])
    promoted = await c.app.promote(PromoteMLModelCommand(tid, mid, "admin", ("analytics:admin",)))
    assert promoted["status"] == "DEPLOYED"
    asset = str(uuid4())
    result = await c.app.run_inference(
        tid,
        "ANOMALY_DETECTOR",
        [
            {
                "asset_ref_id": asset,
                "exposure_score": 5,
                "vuln_count": 2,
                "detection_gap": 1,
                "ai_risk": 3,
            }
        ],
        ("analytics:analyst",),
    )
    assert result["status"] == "OK"
    assert result["count"] == 1
    assert len(c.graph.nodes) == 1


@pytest.mark.asyncio
async def test_promotion_requires_admin() -> None:
    c = MLPipelineContainer()
    tid = uuid4()
    trained = await c.app.schedule_training(
        ScheduleMLModelTrainingCommand(tid, "ANOMALY_DETECTOR", None, ("analytics:admin",), ())
    )
    with pytest.raises(ApplicationForbiddenError):
        await c.app.promote(
            PromoteMLModelCommand(tid, UUID(trained["model_id"]), "x", ("analytics:viewer",))
        )


@pytest.mark.asyncio
async def test_cold_start_awaiting_model() -> None:
    c = MLPipelineContainer()
    tid = uuid4()
    result = await c.app.get_signals(tid, ("analytics:viewer",))
    assert result["status"] == "AWAITING_MODEL"


def test_artifact_integrity_mismatch() -> None:
    svc = MLInferenceService()
    with pytest.raises(ArtifactIntegrityError):
        svc.verify_and_load(b"not-a-model", "0" * 64)


def test_psi_severe_auto_deprecate_threshold() -> None:
    svc = DriftDetectionService()
    expected = [1.0] * 50
    actual = [100.0] * 50
    result = svc.compute_psi(expected, actual)
    assert result.severe is True
    assert result.psi >= 0.20


@pytest.mark.asyncio
async def test_drift_auto_deprecates_deployed_model() -> None:
    c = MLPipelineContainer()
    tid = uuid4()
    trained = await c.app.schedule_training(
        ScheduleMLModelTrainingCommand(tid, "ANOMALY_DETECTOR", None, ("analytics:admin",), ())
    )
    mid = UUID(trained["model_id"])
    await c.app.promote(PromoteMLModelCommand(tid, mid, "admin", ("analytics:admin",)))
    drift = await c.app.check_drift(tid, mid, [999.0] * 40)
    assert drift["severe"] is True
    assert drift["status"] == "DEPRECATED"


@pytest.mark.asyncio
async def test_artifact_tenant_isolation() -> None:
    c = MLPipelineContainer()
    tid = uuid4()
    trained = await c.app.schedule_training(
        ScheduleMLModelTrainingCommand(tid, "ANOMALY_DETECTOR", None, ("analytics:admin",), ())
    )
    mid = UUID(trained["model_id"])
    with pytest.raises(ArtifactNotFoundError):
        await c.artifacts.load_artifact(uuid4(), mid)


@pytest.mark.asyncio
async def test_training_worker_dedup() -> None:
    c = MLPipelineContainer()
    tid = uuid4()
    r1 = await c.training_worker.run(job_id="j1", tenant_id=tid, model_type="ANOMALY_DETECTOR")
    r2 = await c.training_worker.run(job_id="j1", tenant_id=tid, model_type="ANOMALY_DETECTOR")
    assert r1["deduplicated"] is False
    assert r2["deduplicated"] is True
