"""ITechniqueExecutionPort — dispatch AttackAction to a worker (stub in Phase 4)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.value_objects.execution_vos import ActionInput, WorkerRef
    from execution.domain.value_objects.identifiers import AttackActionId


class ITechniqueExecutionPort(ABC):
    @abstractmethod
    async def dispatch(
        self,
        action_id: AttackActionId,
        worker_ref: WorkerRef,
        action_input: ActionInput,
        *,
        payload_id: UUID | None = None,
        expected_payload_hash: str | None = None,
    ) -> None:
        """Accept assignment; optional payload_id for dispatch-time re-verify."""
        ...

    @abstractmethod
    async def signal_abort(self, action_id: AttackActionId, reason: str) -> None:
        ...
