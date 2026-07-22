from __future__ import annotations

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.value_objects.identifiers import AutomationExecutionId, TenantId


class AutomationOutboxService:
    def create_pending(
        self,
        tenant_id: TenantId,
        execution_id: AutomationExecutionId,
        step_number: int,
        action_type: str,
        connector_type: str,
        target_resource: str,
        parameters: dict[str, object],
    ) -> AutomatedActionRecord:
        return AutomatedActionRecord.create_pending(
            tenant_id,
            execution_id,
            step_number,
            action_type,
            connector_type,
            target_resource,
            parameters,
        )
