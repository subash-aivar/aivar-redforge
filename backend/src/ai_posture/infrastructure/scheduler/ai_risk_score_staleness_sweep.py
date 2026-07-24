"""Scheduled staleness sweep job entrypoint (Phase 2)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_posture.application.commands.posture_commands import RunStalenessSweepCommand
from ai_posture.domain.value_objects.enums import AIPostureRole
from ai_posture.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from ai_posture.application.services.risk_scoring_app_service import (
        RiskScoringApplicationService,
    )


async def run_staleness_sweep_job(
    risk_service: RiskScoringApplicationService,
    tenant_id: TenantId,
    *,
    threat_threshold_days: int = 90,
) -> None:
    await risk_service.run_staleness_sweep(
        RunStalenessSweepCommand(
            tenant_id=tenant_id,
            threat_threshold_days=threat_threshold_days,
            actor_roles=(AIPostureRole.ENGINEER.value,),
        )
    )
