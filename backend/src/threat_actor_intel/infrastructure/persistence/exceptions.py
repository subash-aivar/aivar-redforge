"""Infrastructure-layer persistence errors for threat_actor_intel
(M51.1 Phase 3), mirroring `risk_engine.infrastructure.persistence.
exceptions`'s convention: raw SQLAlchemy/DBAPI errors are translated
at the repository boundary so callers never see a driver-specific
type."""

from __future__ import annotations


class ThreatActorIntelPersistenceError(Exception):
    """Base type for every threat_actor_intel infrastructure
    persistence error."""


class ThreatActorIntelIntegrityError(ThreatActorIntelPersistenceError):
    """Raised when a SQLAlchemy `IntegrityError` (constraint violation
    — e.g. the partial unique index on active associations) is
    translated at the repository boundary."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason
