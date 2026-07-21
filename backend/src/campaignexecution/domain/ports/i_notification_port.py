"""INotificationPort — human approval and campaign pause notifications."""

from __future__ import annotations

from abc import ABC, abstractmethod


class INotificationPort(ABC):
    """Outbound port for human-facing campaignexecution notifications."""

    @abstractmethod
    async def notify_human_approval_gate(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        task_id: str,
        required_approver_role: str,
        gate_timeout_seconds: int,
    ) -> None:
        """Notify approvers that a human approval gate is waiting."""

    @abstractmethod
    async def notify_campaign_paused(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        reason: str,
    ) -> None:
        """Notify operators that campaign execution was paused."""
