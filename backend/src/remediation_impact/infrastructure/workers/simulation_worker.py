"""Background worker helpers for remediation simulation (Phase 4)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from remediation_impact.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from remediation_impact.application.commands.plan_commands import (
        GenerateExposureReductionPlanCommand,
    )
    from remediation_impact.application.dtos.plan_dtos import ExposureReductionPlanDTO
    from remediation_impact.application.services.exposure_reduction_plan_service import (
        ExposureReductionPlanService,
    )


class RemediationSimulationWorker:
    """Async job entry-point for plan generation outside the request path."""

    def __init__(self, plan_service: ExposureReductionPlanService) -> None:
        self._plans = plan_service

    async def generate_async(
        self, cmd: GenerateExposureReductionPlanCommand
    ) -> ExposureReductionPlanDTO:
        return await self._plans.generate(cmd)

    async def list_stale_plans(
        self, tenant_id: TenantId, actor_roles: tuple[str, ...]
    ) -> list[ExposureReductionPlanDTO]:
        plans = await self._plans.list_plans(tenant_id, actor_roles)
        return [p for p in plans if p.is_stale]
