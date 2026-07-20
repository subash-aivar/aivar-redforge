"""ExecutionTimeoutService — mark TimedOut and signal abort."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from execution.domain.aggregates.attack_action import AttackAction
    from execution.domain.ports.i_technique_execution_port import ITechniqueExecutionPort
    from execution.domain.value_objects.identifiers import TenantId


class ExecutionTimeoutService:
    def __init__(self, technique_port: ITechniqueExecutionPort) -> None:
        self._technique_port = technique_port

    def is_timed_out(
        self,
        action: AttackAction,
        now: datetime,
        max_duration: timedelta,
    ) -> bool:
        if action.is_terminal():
            return False
        return (now - action.execution_timestamp) > max_duration

    async def mark_timed_out(
        self,
        action: AttackAction,
        tenant_id: TenantId,
        max_duration_seconds: int,
        now: datetime,
    ) -> None:
        action.mark_timed_out(tenant_id, max_duration_seconds, now)
        await self._technique_port.signal_abort(
            action.action_id, f"Timed out after {max_duration_seconds}s"
        )
