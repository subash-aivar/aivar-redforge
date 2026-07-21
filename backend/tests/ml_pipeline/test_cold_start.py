"""Cold start: no deployed model → AWAITING_MODEL / INSUFFICIENT_TRAINING_DATA (not error)."""

from __future__ import annotations

import pytest

from ml_pipeline.domain.value_objects.enums import MLModelType
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.mark.asyncio
async def test_cold_start_inference_awaiting_model(
    container: MLPipelineContainer, tenant_id, admin_roles
) -> None:
    result = await container.app.run_inference(
        tenant_id,
        MLModelType.RISK_PREDICTOR.value,
        [{"asset_ref_id": str(tenant_id), "exposure_score": 1.0}],
        admin_roles,
    )
    assert result["status"] == "AWAITING_MODEL"
    assert result["reason"] == "INSUFFICIENT_TRAINING_DATA"
    assert result["signals"] == []


@pytest.mark.asyncio
async def test_cold_start_signals_query(
    container: MLPipelineContainer, tenant_id, viewer_roles
) -> None:
    result = await container.app.get_signals(tenant_id, viewer_roles)
    assert result["status"] == "AWAITING_MODEL"
    assert result["reason"] == "INSUFFICIENT_TRAINING_DATA"
