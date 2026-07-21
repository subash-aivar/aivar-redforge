"""TaskDispatchService — translates CampaignTask into M29 operation creation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:

    from campaignexecution.domain.ports.i_operation_creation_port import (
        IOperationCreationPort,
        TaskDispatchRequest,
    )
    from campaignexecution.domain.value_objects.execution_vos import EngagementRef, OperationRef
    from campaignexecution.domain.value_objects.identifiers import (
        CampaignInstanceId,
        CampaignTaskId,
        TenantId,
    )


class TaskDispatchService:
    """Translates a CampaignTask into an M29 CreateOperation command sequence.

    Dispatching is idempotent by (campaign_instance_id, task_id): re-dispatch
    of an already-dispatched task returns the existing OperationRef.
    M30 dispatches; M29 authorizes — this service never bypasses M29 safety.
    """

    async def dispatch(
        self,
        tenant_id: TenantId,
        campaign_instance_id: CampaignInstanceId,
        task_id: CampaignTaskId,
        technique_id: str,
        technique_name: str,
        parameters: dict[str, str],
        engagement_ref: EngagementRef,
        port: IOperationCreationPort,
    ) -> OperationRef:
        """Dispatch a task to M29 by creating an operation via the ACL port.

        The port implementation is responsible for creating, approving, and
        queuing the M29 operation. This service only translates the request.
        """
        request: TaskDispatchRequest = {
            "campaign_instance_id": str(campaign_instance_id),
            "task_id": str(task_id),
            "technique_id": technique_id,
            "technique_name": technique_name,
            "parameters": parameters,
            "engagement_id": str(engagement_ref.engagement_id),
            "tenant_id": str(tenant_id),
        }
        return await port.create_operation(request)
