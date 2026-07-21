"""CampaignPauseCoordinator — handles safety breaches and human approval gates."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from campaignexecution.domain.aggregates.task_graph_execution import TaskGraphExecution
    from campaignexecution.domain.value_objects.execution_vos import PendingApprovalGate
    from campaignexecution.domain.value_objects.identifiers import (
        TenantId,
    )


class CampaignPauseCoordinator:
    """Handles transitions to Paused/WaitingForApproval state.

    Called when:
    - A SafetyPolicyBreached event is raised by the safety monitor
    - A HumanApprovalTask is reached in the execution graph
    - M29 kill switch fires during execution

    This service is stateless; it calls domain methods on TaskGraphExecution.
    """

    def handle_safety_breach(
        self,
        execution: TaskGraphExecution,
        tenant_id: TenantId,
        breach_type: str,
        details: str,
        now: datetime,
    ) -> None:
        """Record the safety breach and pause the execution."""
        from campaignexecution.domain.value_objects.enums import ExecutionState

        execution.breach_safety_policy(tenant_id, breach_type, details, now)
        if execution.state == ExecutionState.RUNNING:
            execution.pause(tenant_id, f"Safety breach: {breach_type}", now)

    def handle_human_approval_gate(
        self,
        execution: TaskGraphExecution,
        tenant_id: TenantId,
        pending_gate: PendingApprovalGate,
        now: datetime,
    ) -> None:
        """Transition execution to WaitingForApproval state."""
        execution.reach_human_approval_gate(tenant_id, pending_gate, now)

    def handle_kill_switch_triggered(
        self,
        execution: TaskGraphExecution,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        """M29 kill switch triggered → pause all pending dispatches."""
        from campaignexecution.domain.value_objects.enums import ExecutionState

        if execution.state == ExecutionState.RUNNING:
            execution.pause(tenant_id, "M29 kill switch triggered", now)
