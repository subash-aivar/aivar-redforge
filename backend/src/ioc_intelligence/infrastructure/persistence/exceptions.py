"""Infrastructure-layer persistence errors for ioc_intelligence
(M51.2 Phase A3), mirroring `threat_actor_intel.infrastructure.
persistence.exceptions`'s convention: raw SQLAlchemy/DBAPI errors are
translated at the repository boundary so callers never see a
driver-specific type."""

from __future__ import annotations


class IocIntelPersistenceError(Exception):
    """Base type for every ioc_intelligence infrastructure persistence
    error."""


class IocIntelIntegrityError(IocIntelPersistenceError):
    """Raised when a SQLAlchemy `IntegrityError` (constraint violation
    — e.g. a duplicate global/tenant identity, a duplicate source
    attribution, or a duplicate evidence citation) is translated at
    the repository boundary."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason


class OptimisticLockConflictError(IocIntelPersistenceError):
    """Raised when a `save()` call's expected `row_version` no longer
    matches the persisted row — a concurrent writer already updated
    this IOC. The caller must reload and retry; the repository never
    reports success after a lost update."""

    def __init__(self, ioc_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on IOC {ioc_id}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.ioc_id = ioc_id
        self.expected_version = expected_version
        self.actual_version = actual_version
