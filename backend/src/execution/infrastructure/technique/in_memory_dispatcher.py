"""In-memory technique execution dispatcher (Phase 4 stub — no real techniques)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.ports.i_technique_execution_port import ITechniqueExecutionPort

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.value_objects.execution_vos import ActionInput, WorkerRef
    from execution.domain.value_objects.identifiers import AttackActionId


class InMemoryTechniqueDispatcher(ITechniqueExecutionPort):
    def __init__(self) -> None:
        self.dispatched: list[tuple[str, str, str | None, str | None]] = []
        self.aborted: list[tuple[str, str]] = []

    async def dispatch(
        self,
        action_id: AttackActionId,
        worker_ref: WorkerRef,
        action_input: ActionInput,
        *,
        payload_id: UUID | None = None,
        expected_payload_hash: str | None = None,
    ) -> None:
        _ = action_input
        self.dispatched.append(
            (
                str(action_id),
                str(worker_ref.worker_id),
                str(payload_id) if payload_id is not None else None,
                expected_payload_hash,
            )
        )

    async def signal_abort(self, action_id: AttackActionId, reason: str) -> None:
        self.aborted.append((str(action_id), reason))
