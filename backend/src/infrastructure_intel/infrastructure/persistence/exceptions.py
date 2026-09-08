"""Infrastructure-layer persistence errors for infrastructure_intel,
mirroring `tool_intel.infrastructure.persistence.exceptions`'s
convention."""

from __future__ import annotations


class InfrastructureIntelPersistenceError(Exception):
    """Base type for every infrastructure_intel infrastructure
    persistence error."""


class InfrastructureIntelIntegrityError(InfrastructureIntelPersistenceError):
    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason


class OptimisticLockConflictError(InfrastructureIntelPersistenceError):
    """Raised when a `save()` call's expected `row_version` no longer
    matches the persisted row — a concurrent writer already updated this
    Infrastructure record. The caller must reload and retry."""

    def __init__(self, infrastructure_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on Infrastructure {infrastructure_id}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.infrastructure_id = infrastructure_id
        self.expected_version = expected_version
        self.actual_version = actual_version
