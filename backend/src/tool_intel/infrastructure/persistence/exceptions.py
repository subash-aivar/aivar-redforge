"""Infrastructure-layer persistence errors for tool_intel, mirroring
`campaign_intel.infrastructure.persistence.exceptions`'s convention."""

from __future__ import annotations


class ToolIntelPersistenceError(Exception):
    """Base type for every tool_intel infrastructure persistence
    error."""


class ToolIntelIntegrityError(ToolIntelPersistenceError):
    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason


class OptimisticLockConflictError(ToolIntelPersistenceError):
    """Raised when a `save()` call's expected `row_version` no longer
    matches the persisted row — a concurrent writer already updated this
    Tool. The caller must reload and retry."""

    def __init__(self, tool_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on Tool {tool_id}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.tool_id = tool_id
        self.expected_version = expected_version
        self.actual_version = actual_version
