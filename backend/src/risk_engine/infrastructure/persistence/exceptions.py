"""Infrastructure-layer persistence errors for risk_engine (M48E).

Deliberately declared in `infrastructure/`, not `domain/exceptions/`
or `application/exceptions.py` — both of those modules are frozen by
M48A-D and an optimistic-locking conflict or a raw-DB-error
translation is an infrastructure concern the frozen domain/application
layers never anticipated, mirroring how `credential_vault` keeps
`OptimisticLockConflict` in its own `domain_exceptions.py` only
because that context's domain layer was designed with persistence
concurrency in mind from the start; risk_engine's frozen domain layer
was not, so this milestone adds the equivalent error at the layer it
actually owns instead of reopening a frozen file.
"""

from __future__ import annotations


class RiskEnginePersistenceError(Exception):
    """Base type for every risk_engine infrastructure persistence error."""


class RiskEngineOptimisticLockError(RiskEnginePersistenceError):
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


class RiskEngineIntegrityError(RiskEnginePersistenceError):
    """Raised when a SQLAlchemy `IntegrityError` (constraint
    violation) is translated at the repository boundary — callers see
    a risk_engine-specific error, never a raw SQLAlchemy/DBAPI type."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason
