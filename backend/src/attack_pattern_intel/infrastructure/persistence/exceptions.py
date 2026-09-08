"""Infrastructure-layer persistence errors for attack_pattern_intel
(M51.3 Phase B1), mirroring `ioc_intelligence.infrastructure.
persistence.exceptions`'s convention."""

from __future__ import annotations


class AttackPatternIntelPersistenceError(Exception):
    """Base type for every attack_pattern_intel infrastructure
    persistence error."""


class AttackPatternIntelIntegrityError(AttackPatternIntelPersistenceError):
    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason


class OptimisticLockConflictError(AttackPatternIntelPersistenceError):
    """Raised when a `save()` call's expected `row_version` no longer
    matches the persisted row — a concurrent writer already updated
    this AttackPattern. The caller must reload and retry."""

    def __init__(self, attack_pattern_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on AttackPattern {attack_pattern_id}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.attack_pattern_id = attack_pattern_id
        self.expected_version = expected_version
        self.actual_version = actual_version
