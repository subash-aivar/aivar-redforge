"""Infrastructure-layer persistence errors for attack_surface_management
(M49C), mirroring `risk_engine.infrastructure.persistence.exceptions`
exactly. Deliberately declared in `infrastructure/`, not
`domain/exceptions/` or `application/exceptions.py` — both are frozen
by M49A/M49B and a raw-DB-error translation is an infrastructure
concern those frozen layers never anticipated."""

from __future__ import annotations


class AttackSurfacePersistenceError(Exception):
    """Base type for every attack_surface_management infrastructure
    persistence error."""


class AttackSurfaceOptimisticLockError(AttackSurfacePersistenceError):
    """Raised when a `save()` targets a row whose `row_version` no
    longer matches what the in-memory aggregate was loaded with —
    another writer committed a concurrent change first."""

    def __init__(self, aggregate_id: object, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict for {aggregate_id!r}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.aggregate_id = aggregate_id
        self.expected_version = expected_version
        self.actual_version = actual_version


class AttackSurfaceIntegrityError(AttackSurfacePersistenceError):
    """Raised when a SQLAlchemy `IntegrityError` (constraint violation)
    is translated at the repository boundary — callers see an
    attack_surface_management-specific error, never a raw
    SQLAlchemy/DBAPI type."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason
