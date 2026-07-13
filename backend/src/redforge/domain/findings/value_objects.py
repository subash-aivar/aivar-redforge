"""Value objects for the Finding bounded context.

Findings are derived security assessments. These value objects capture
severity, status, risk scoring, and compliance framework references.
"""

from dataclasses import dataclass
from enum import StrEnum, unique


@unique
class Severity(StrEnum):
    """Severity classification for a security finding.

    Aligned with industry-standard vulnerability severity levels.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@unique
class FindingStatus(StrEnum):
    """Lifecycle status of a Finding.

    - OPEN: Finding is active and unresolved.
    - ACCEPTED: Risk has been accepted by the organization.
    - CLOSED: Finding has been resolved or mitigated.
    - REOPENED: A previously closed finding was reopened.
    """

    OPEN = "open"
    ACCEPTED = "accepted"
    CLOSED = "closed"
    REOPENED = "reopened"


@dataclass(frozen=True, slots=True)
class RiskScore:
    """Quantified risk score for a finding.

    Combines likelihood and impact into a single score.
    Scale: 0.0 (no risk) to 10.0 (maximum risk).
    """

    score: float

    def __post_init__(self) -> None:
        if self.score < 0.0 or self.score > 10.0:
            raise ValueError(
                f"Risk score must be between 0.0 and 10.0, got {self.score}"
            )

    @property
    def severity_level(self) -> Severity:
        """Map numeric score to severity level."""
        if self.score >= 9.0:
            return Severity.CRITICAL
        if self.score >= 7.0:
            return Severity.HIGH
        if self.score >= 4.0:
            return Severity.MEDIUM
        if self.score >= 1.0:
            return Severity.LOW
        return Severity.INFORMATIONAL


@dataclass(frozen=True, slots=True)
class ComplianceReference:
    """Reference to a compliance framework requirement.

    Examples: SOC2 CC6.1, ISO 27001 A.12.6.1, NIST AI 600-1
    """

    framework: str
    requirement_id: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.framework:
            raise ValueError("framework must not be empty")
        if not self.requirement_id:
            raise ValueError("requirement_id must not be empty")


@dataclass(frozen=True, slots=True)
class MitreReference:
    """Reference to a MITRE ATLAS technique.

    Links findings to the MITRE ATLAS framework for AI/ML threats.
    """

    technique_id: str
    technique_name: str
    tactic: str = ""

    def __post_init__(self) -> None:
        if not self.technique_id:
            raise ValueError("technique_id must not be empty")
        if not self.technique_name:
            raise ValueError("technique_name must not be empty")


@dataclass(frozen=True, slots=True)
class OwaspReference:
    """Reference to an OWASP LLM Top 10 category.

    Links findings to the OWASP Top 10 for LLM Applications.
    """

    category_id: str
    category_name: str

    def __post_init__(self) -> None:
        if not self.category_id:
            raise ValueError("category_id must not be empty")
        if not self.category_name:
            raise ValueError("category_name must not be empty")
