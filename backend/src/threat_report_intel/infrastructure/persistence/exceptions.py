"""Infrastructure-layer persistence errors for threat_report_intel,
mirroring `infrastructure_intel.infrastructure.persistence.exceptions`'s
convention."""

from __future__ import annotations


class ThreatReportIntelPersistenceError(Exception):
    """Base type for every threat_report_intel infrastructure
    persistence error."""


class ThreatReportIntelIntegrityError(ThreatReportIntelPersistenceError):
    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason


class OptimisticLockConflictError(ThreatReportIntelPersistenceError):
    """Raised when a `save()` call's expected `row_version` no longer
    matches the persisted row — a concurrent writer already updated this
    ThreatReport record. The caller must reload and retry."""

    def __init__(self, threat_report_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on ThreatReport {threat_report_id}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.threat_report_id = threat_report_id
        self.expected_version = expected_version
        self.actual_version = actual_version
