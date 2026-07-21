"""IOperationCreationPort — ACL port for creating M29 operations from campaign tasks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from campaignexecution.domain.value_objects.execution_vos import OperationRef


class TaskDispatchRequest(TypedDict):
    """Request payload for dispatching a campaign task to M29."""

    campaign_instance_id: str
    task_id: str
    technique_id: str
    technique_name: str
    parameters: dict[str, str]
    engagement_id: str
    tenant_id: str


class IOperationCreationPort(ABC):
    """ACL interface to M29's operation context.

    Implementations translate a TaskDispatchRequest into an M29
    CreateOperation + ApproveOperation + QueueOperation command sequence.
    M30 dispatches; M29 independently authorizes via ExecutionAuthorizationService.
    """

    @abstractmethod
    async def create_operation(
        self,
        request: TaskDispatchRequest,
    ) -> OperationRef:
        """Create an M29 operation for the given task and return the OperationRef.

        This port must be idempotent by (campaign_instance_id, task_id):
        re-dispatch returns the existing OperationRef if already created.
        """
