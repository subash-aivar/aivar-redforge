"""Domain exceptions for the TaskGraph bounded context."""

from __future__ import annotations


class TaskGraphDomainException(Exception):
    """Base for all TaskGraph domain exceptions."""


class InvalidStateTransition(TaskGraphDomainException):
    def __init__(self, from_state: str, to_state: str, graph_id: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        self.graph_id = graph_id
        super().__init__(f"Cannot transition from {from_state} to {to_state} on graph {graph_id}")


class SignedGraphImmutabilityViolation(TaskGraphDomainException):
    def __init__(self, graph_id: str) -> None:
        self.graph_id = graph_id
        super().__init__(f"Task graph {graph_id} is Signed or beyond — topology is immutable")


class TaskGraphValidationFailed(TaskGraphDomainException):
    def __init__(self, graph_id: str, errors: list[str]) -> None:
        self.graph_id = graph_id
        self.errors = errors
        super().__init__(f"Task graph {graph_id} validation failed: {'; '.join(errors)}")


class CycleDetectedError(TaskGraphDomainException):
    def __init__(self, description: str) -> None:
        self.description = description
        super().__init__(f"Cycle detected in task graph: {description}")


class InvalidArgument(TaskGraphDomainException):
    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid {field}: {reason}")


class TenantMismatch(TaskGraphDomainException):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class TaskNotFound(TaskGraphDomainException):
    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        super().__init__(f"Task not found: {task_id}")


class DuplicateTask(TaskGraphDomainException):
    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        super().__init__(f"Task already exists in graph: {task_id}")


class OptimisticLockConflict(TaskGraphDomainException):
    def __init__(self, graph_id: str, expected: int, actual: int) -> None:
        self.graph_id = graph_id
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Optimistic lock conflict on graph {graph_id}: "
            f"expected version {expected}, found {actual}"
        )
