"""Degraded (stub) ACL adapters for campaignexecution context.

Used in tests and as fallbacks when M29 is unavailable.
These adapters must NEVER be used in production — production code must
inject real M29-backed adapters.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import uuid7

from campaignexecution.domain.ports.i_attack_action_query_port import IAttackActionQueryPort
from campaignexecution.domain.ports.i_notification_port import INotificationPort
from campaignexecution.domain.ports.i_operation_creation_port import IOperationCreationPort
from campaignexecution.domain.value_objects.enums import TaskOutcome
from campaignexecution.domain.value_objects.execution_vos import OperationRef

if TYPE_CHECKING:
    from campaignexecution.domain.ports.i_operation_creation_port import TaskDispatchRequest

log = logging.getLogger(__name__)


class StubNotificationAdapter(INotificationPort):
    """Records notification calls for tests — does not send real notifications."""

    def __init__(self) -> None:
        self.approval_gates: list[dict[str, object]] = []
        self.pauses: list[dict[str, str]] = []

    async def notify_human_approval_gate(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        task_id: str,
        required_approver_role: str,
        gate_timeout_seconds: int,
    ) -> None:
        self.approval_gates.append(
            {
                "tenant_id": tenant_id,
                "execution_id": execution_id,
                "task_id": task_id,
                "required_approver_role": required_approver_role,
                "gate_timeout_seconds": gate_timeout_seconds,
            }
        )

    async def notify_campaign_paused(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        reason: str,
    ) -> None:
        self.pauses.append(
            {
                "tenant_id": tenant_id,
                "execution_id": execution_id,
                "reason": reason,
            }
        )


class StubOperationCreationAdapter(IOperationCreationPort):
    """Creates stub operations for testing — does NOT create real M29 operations.

    Idempotent by (campaign_instance_id, task_id): same key → same OperationRef.
    """

    def __init__(self, tenant_id_override: str | None = None) -> None:
        self._cache: dict[tuple[str, str], OperationRef] = {}
        self._tenant_override = tenant_id_override

    async def create_operation(self, request: TaskDispatchRequest) -> OperationRef:
        from uuid import UUID

        key = (request["campaign_instance_id"], request["task_id"])
        if key not in self._cache:
            tid_str = self._tenant_override or request["tenant_id"]
            self._cache[key] = OperationRef(
                operation_id=uuid7(),
                tenant_id=UUID(tid_str),
            )
            log.debug(
                "StubOperationCreationAdapter: created operation %s",
                self._cache[key].operation_id,
            )
        return self._cache[key]


class StubAttackActionQueryAdapter(IAttackActionQueryPort):
    """Returns configurable outcomes for testing."""

    def __init__(self, default_outcome: TaskOutcome = TaskOutcome.SUCCESS) -> None:
        self._outcomes: dict[str, TaskOutcome] = {}
        self._default = default_outcome
        self._detection_events: dict[str, list[str]] = {}

    def set_outcome(self, operation_id: str, outcome: TaskOutcome) -> None:
        self._outcomes[operation_id] = outcome

    def set_detection_events(self, operation_id: str, event_ids: list[str]) -> None:
        self._detection_events[operation_id] = event_ids

    async def get_action_outcome(self, operation_ref: OperationRef) -> TaskOutcome | None:
        return self._outcomes.get(str(operation_ref.operation_id), self._default)

    async def get_detection_events(self, operation_ref: OperationRef) -> list[str]:
        return self._detection_events.get(str(operation_ref.operation_id), [])
