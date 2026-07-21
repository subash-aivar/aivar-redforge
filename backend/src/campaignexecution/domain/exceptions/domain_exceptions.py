"""campaignexecution domain exceptions.

Exception names follow DDD ubiquitous-language naming from the architecture spec
(e.g. InvalidStateTransition, BarrierNotPassable) rather than the PEP-8 *Error suffix
convention — N818 is suppressed file-wide intentionally.
"""

# ruff: noqa: N818
from __future__ import annotations


class CampaignExecutionDomainException(Exception):
    """Base class for all campaignexecution domain exceptions."""


class InvalidStateTransition(CampaignExecutionDomainException):
    def __init__(self, from_state: str, operation: str, aggregate_id: str) -> None:
        super().__init__(
            f"Cannot perform '{operation}' on execution '{aggregate_id}' in state '{from_state}'"
        )
        self.from_state = from_state
        self.operation = operation
        self.aggregate_id = aggregate_id


class TenantMismatch(CampaignExecutionDomainException):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class TaskNotFound(CampaignExecutionDomainException):
    def __init__(self, task_id: str) -> None:
        super().__init__(f"Task not found in execution: {task_id}")
        self.task_id = task_id


class TaskAlreadyDispatched(CampaignExecutionDomainException):
    def __init__(self, task_id: str) -> None:
        super().__init__(f"Task already dispatched: {task_id}")
        self.task_id = task_id


class TaskNotReadyToDispatch(CampaignExecutionDomainException):
    def __init__(self, task_id: str, state: str) -> None:
        super().__init__(f"Task '{task_id}' is not ready to dispatch (state: {state})")
        self.task_id = task_id
        self.state = state


class BarrierNotPassable(CampaignExecutionDomainException):
    def __init__(self, barrier_task_id: str, pending_count: int) -> None:
        super().__init__(
            f"Barrier '{barrier_task_id}' cannot pass: {pending_count} tasks still pending"
        )


class SafetyPolicyViolation(CampaignExecutionDomainException):
    def __init__(self, policy_field: str, message: str) -> None:
        super().__init__(f"Safety policy violation [{policy_field}]: {message}")
        self.policy_field = policy_field


class ConcurrencyConflict(CampaignExecutionDomainException):
    def __init__(self, aggregate_id: str) -> None:
        super().__init__(
            f"Optimistic locking conflict on execution '{aggregate_id}' — retry required"
        )


class NoApprovalGatePending(CampaignExecutionDomainException):
    def __init__(self, execution_id: str) -> None:
        super().__init__(f"No human approval gate pending for execution '{execution_id}'")


class RollbackNotAllowed(CampaignExecutionDomainException):
    def __init__(self, state: str) -> None:
        super().__init__(
            f"Rollback may only be initiated from Paused or Failed state, not '{state}'"
        )


class MonitorAutoAbortAlreadyTriggered(CampaignExecutionDomainException):
    def __init__(self, monitor_id: str) -> None:
        super().__init__(
            f"Safety monitor '{monitor_id}' has already triggered auto-abort — irreversible"
        )
