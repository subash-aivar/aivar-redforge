"""IExposureReductionPlanRepository — inbound port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from remediation_impact.domain.aggregates.exposure_reduction_plan import (
        ExposureReductionPlan,
    )
    from remediation_impact.domain.value_objects.identifiers import (
        ExposureReductionPlanId,
        TenantId,
    )


class IExposureReductionPlanRepository(ABC):
    @abstractmethod
    async def get(
        self, tenant_id: TenantId, plan_id: ExposureReductionPlanId
    ) -> ExposureReductionPlan | None: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, plan: ExposureReductionPlan) -> None: ...

    @abstractmethod
    async def list_by_tenant(
        self, tenant_id: TenantId, *, status_filter: str | None = None
    ) -> list[ExposureReductionPlan]: ...
