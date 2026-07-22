from __future__ import annotations

from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class ModelGovernanceService:
    def deploy(
        self,
        model: OptimizationModel,
        tenant_id: TenantId,
        conformity_assessment_ref: str,
    ) -> None:
        model.deploy(tenant_id, conformity_assessment_ref)

    def deprecate(
        self, model: OptimizationModel, tenant_id: TenantId, superseded_by_version: int
    ) -> None:
        model.deprecate(tenant_id, superseded_by_version)
