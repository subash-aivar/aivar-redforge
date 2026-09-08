"""Infrastructure-layer persistence errors for
intelligence_relationships (M51.4 Phase C1), mirroring
`attack_pattern_intel.infrastructure.persistence.exceptions`'s
convention."""

from __future__ import annotations


class IntelligenceRelationshipsPersistenceError(Exception):
    """Base type for every intelligence_relationships infrastructure
    persistence error."""


class IntelligenceRelationshipsIntegrityError(IntelligenceRelationshipsPersistenceError):
    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason


class OptimisticLockConflictError(IntelligenceRelationshipsPersistenceError):
    """Raised when a `save()` call's expected `row_version` no longer
    matches the persisted row — a concurrent writer already updated
    this relationship. The caller must reload and retry."""

    def __init__(self, relationship_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on IntelligenceRelationship {relationship_id}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.relationship_id = relationship_id
        self.expected_version = expected_version
        self.actual_version = actual_version
