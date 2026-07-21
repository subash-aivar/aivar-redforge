"""IAttackActionQueryPort — ACL port for querying M29 attack action outcomes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaignexecution.domain.value_objects.enums import TaskOutcome
    from campaignexecution.domain.value_objects.execution_vos import OperationRef


class IAttackActionQueryPort(ABC):
    """ACL interface to M29's execution context for querying AttackAction outcomes.

    Used by the execution service to poll operation completion status
    and retrieve outcomes for conditional branch evaluation.
    """

    @abstractmethod
    async def get_action_outcome(
        self,
        operation_ref: OperationRef,
    ) -> TaskOutcome | None:
        """Return the current outcome of an M29 operation, or None if still running."""

    @abstractmethod
    async def get_detection_events(
        self,
        operation_ref: OperationRef,
    ) -> list[str]:
        """Return detection event IDs associated with this operation from M28.

        Used by safety monitor to check if auto_abort_on_detection should trigger.
        Returns empty list if no detections.
        """
