"""PredictiveRiskSignal expiry — expired signals not served (TTL 30 days)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ml_pipeline.domain.aggregates.predictive_risk_signal import PredictiveRiskSignal
from ml_pipeline.domain.value_objects.identifiers import (
    MLModelId,
    PredictiveRiskSignalId,
    TenantId,
)
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.mark.asyncio
async def test_expired_signals_not_served(
    container: MLPipelineContainer, tenant_id, viewer_roles
) -> None:
    now = datetime.now(UTC)
    expired = PredictiveRiskSignal(
        PredictiveRiskSignalId.generate(),
        TenantId(tenant_id),
        MLModelId.generate(),
        uuid4(),
        "RISK_PREDICTOR",
        0.9,
        0.8,
        now - timedelta(days=40),
        now - timedelta(days=10),
        {"exposure_score": 1.0},
    )
    active = PredictiveRiskSignal(
        PredictiveRiskSignalId.generate(),
        TenantId(tenant_id),
        MLModelId.generate(),
        uuid4(),
        "RISK_PREDICTOR",
        0.7,
        0.8,
        now,
        now + timedelta(days=30),
        {"exposure_score": 1.0},
    )
    await container.signals.save_many(TenantId(tenant_id), [expired, active])
    rows = await container.signals.find_active_by_type(
        TenantId(tenant_id), "RISK_PREDICTOR", now=now
    )
    assert len(rows) == 1
    assert rows[0].signal_id == active.signal_id
    assert not expired.is_active(now)
    assert active.is_active(now)
