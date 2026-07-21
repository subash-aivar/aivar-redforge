from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ml_pipeline.domain.aggregates.ml_model import MLModel
    from ml_pipeline.domain.value_objects.identifiers import TenantId


class ModelGovernanceService:
    def promote(self, model: MLModel, tenant_id: TenantId, *, by: str) -> None:
        model.promote(tenant_id, deployed_by=by, at=datetime.now(UTC))

    def deprecate(self, model: MLModel, tenant_id: TenantId, *, by: str) -> None:
        model.deprecate(tenant_id, deprecated_by=by, at=datetime.now(UTC))

    def history(self, model: MLModel) -> list[dict[str, object]]:
        return list(model.governance_history)
