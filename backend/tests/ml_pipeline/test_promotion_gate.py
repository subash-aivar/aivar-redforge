"""Promotion gate — TRAINED → DEPLOYED requires analytics:admin; no auto-promote (ADR-M33-006)."""

from __future__ import annotations

from uuid import UUID

import pytest

from ml_pipeline.application.commands.ml_commands import (
    PromoteMLModelCommand,
    ScheduleMLModelTrainingCommand,
)
from ml_pipeline.application.exceptions import ApplicationForbiddenError
from ml_pipeline.domain.value_objects.enums import MLModelStatus, MLModelType
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.mark.asyncio
async def test_no_auto_promote_after_training(
    container: MLPipelineContainer, tenant_id, admin_roles
) -> None:
    result = await container.app.schedule_training(
        ScheduleMLModelTrainingCommand(
            tenant_id, MLModelType.RISK_PREDICTOR.value, None, admin_roles
        )
    )
    assert result["status"] == MLModelStatus.TRAINED.value


@pytest.mark.asyncio
async def test_promote_requires_admin(
    container: MLPipelineContainer, tenant_id, admin_roles, viewer_roles
) -> None:
    trained = await container.app.schedule_training(
        ScheduleMLModelTrainingCommand(
            tenant_id, MLModelType.RISK_PREDICTOR.value, None, admin_roles
        )
    )
    mid = UUID(trained["model_id"])
    with pytest.raises(ApplicationForbiddenError):
        await container.app.promote(PromoteMLModelCommand(tenant_id, mid, "viewer", viewer_roles))
    promoted = await container.app.promote(
        PromoteMLModelCommand(tenant_id, mid, "admin", admin_roles)
    )
    assert promoted["status"] == MLModelStatus.DEPLOYED.value
    history = await container.app.governance_history(tenant_id, mid, admin_roles)
    assert any(h.get("action") == "promoted" for h in history)
