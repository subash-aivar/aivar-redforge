"""Finding bounded context.

Findings are derived security assessments generated from Evidence.
They are NOT the source of truth — Evidence is. Findings can always
be regenerated from Evidence without data loss.

Public API:
    - Finding: Aggregate root with lifecycle behavior.
    - FindingRepository: Persistence interface (Protocol).
    - Value objects: Severity, FindingStatus, RiskScore, etc.
    - Events: FindingCreated, FindingClosed, etc.
    - Exceptions: FindingNotFoundError, etc.
"""

from redforge.domain.findings.entity import Finding
from redforge.domain.findings.repository import FindingRepository
from redforge.domain.findings.value_objects import (
    ComplianceReference,
    FindingStatus,
    MitreReference,
    OwaspReference,
    RiskScore,
    Severity,
)

__all__ = [
    "ComplianceReference",
    "Finding",
    "FindingRepository",
    "FindingStatus",
    "MitreReference",
    "OwaspReference",
    "RiskScore",
    "Severity",
]
