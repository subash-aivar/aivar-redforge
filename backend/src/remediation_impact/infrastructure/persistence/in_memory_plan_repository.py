"""In-memory IExposureReductionPlanRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from remediation_impact.domain.repositories.i_exposure_reduction_plan_repository import (
    IExposureReductionPlanRepository,
)

if TYPE_CHECKING:
    from remediation_impact.domain.aggregates.exposure_reduction_plan import (
        ExposureReductionPlan,
    )
    from remediation_impact.domain.value_objects.identifiers import (
        ExposureReductionPlanId,
        TenantId,
    )


class InMemoryExposureReductionPlanRepository(IExposureReductionPlanRepository):
    def __init__(self) -> None:
        self._plans: dict[str, dict[str, ExposureReductionPlan]] = {}

    async def get(
        self, tenant_id: TenantId, plan_id: ExposureReductionPlanId
    ) -> ExposureReductionPlan | None:
        return self._plans.get(str(tenant_id), {}).get(str(plan_id))

    async def save(self, tenant_id: TenantId, plan: ExposureReductionPlan) -> None:
        bucket = self._plans.setdefault(str(tenant_id), {})
        bucket[str(plan.plan_id)] = plan

    async def list_by_tenant(
        self, tenant_id: TenantId, *, status_filter: str | None = None
    ) -> list[ExposureReductionPlan]:
        rows = list(self._plans.get(str(tenant_id), {}).values())
        if status_filter:
            rows = [p for p in rows if p.status.value == status_filter]
        return sorted(rows, key=lambda p: p.generated_at, reverse=True)
