"""Artifact SHA-256 integrity mismatch and tenant isolation."""

from __future__ import annotations

from uuid import uuid4

import pytest

from ml_pipeline.application.commands.ml_commands import (
    PromoteMLModelCommand,
    ScheduleMLModelTrainingCommand,
)
from ml_pipeline.domain.exceptions.domain_exceptions import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
)
from ml_pipeline.domain.value_objects.enums import MLModelType
from ml_pipeline.infrastructure.container import MLPipelineContainer


async def _train_and_promote(container, tenant_id, admin_roles):
    trained = await container.app.schedule_training(
        ScheduleMLModelTrainingCommand(
            tenant_id,
            MLModelType.RISK_PREDICTOR.value,
            None,
            admin_roles,
        )
    )
    assert trained["status"] == "TRAINED"
    mid = trained["model_id"]
    from uuid import UUID

    await container.app.promote(PromoteMLModelCommand(tenant_id, UUID(mid), "admin", admin_roles))
    return UUID(mid)


@pytest.mark.asyncio
async def test_artifact_integrity_mismatch(
    container: MLPipelineContainer, tenant_id, admin_roles
) -> None:
    model_id = await _train_and_promote(container, tenant_id, admin_roles)
    container.artifacts.corrupt_for_test(tenant_id, model_id)
    with pytest.raises(ArtifactIntegrityError):
        await container.app.run_inference(
            tenant_id,
            MLModelType.RISK_PREDICTOR.value,
            [
                {
                    "asset_ref_id": str(uuid4()),
                    "exposure_score": 5.0,
                    "vuln_count": 2.0,
                    "detection_gap": 1.0,
                    "ai_risk": 1.0,
                }
            ],
            admin_roles,
        )


@pytest.mark.asyncio
async def test_artifact_tenant_isolation(
    container: MLPipelineContainer, tenant_id, admin_roles
) -> None:
    model_id = await _train_and_promote(container, tenant_id, admin_roles)
    other = uuid4()
    with pytest.raises(ArtifactNotFoundError):
        await container.artifacts.load_artifact(other, model_id)
