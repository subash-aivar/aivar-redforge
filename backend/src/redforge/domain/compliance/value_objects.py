"""Value objects for the Compliance bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Any


@unique
class FrameworkKey(StrEnum):
    """Canonical identifier for each supported compliance framework.

    The string value is stable and used as the lookup key in the
    FrameworkDefinitionPort adapter registry.  Adding a new framework
    in a future sprint only requires adding an enum value and a matching
    JSON fixture — no other domain code changes.
    """

    SOC2 = "soc2_type2"
    ISO27001 = "iso27001_2022"
    NIST_CSF = "nist_csf_2_0"
    CIS = "cis_benchmarks_v8"
    HIPAA = "hipaa_security_rule"


@unique
class FrameworkStatus(StrEnum):
    """Publication lifecycle for a FrameworkDefinition.

    DRAFT        — loaded from adapter but not yet published to catalog.
    PUBLISHED    — live; organizations can map assessments to this framework.
    RETIRED      — superseded or withdrawn; read-only, no new assessments.
    """

    DRAFT = "draft"
    PUBLISHED = "published"
    RETIRED = "retired"


@unique
class ControlDomain(StrEnum):
    """High-level security domain grouping for a ControlRequirement.

    Kept broad and cross-framework so that mappings between frameworks
    remain meaningful.  Adapters map their own categories to these values.
    """

    ACCESS_CONTROL = "access_control"
    AUDIT_LOGGING = "audit_logging"
    CHANGE_MANAGEMENT = "change_management"
    CRYPTOGRAPHY = "cryptography"
    DATA_PROTECTION = "data_protection"
    INCIDENT_RESPONSE = "incident_response"
    NETWORK_SECURITY = "network_security"
    PHYSICAL_SECURITY = "physical_security"
    RISK_MANAGEMENT = "risk_management"
    SUPPLY_CHAIN = "supply_chain"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    OTHER = "other"


@unique
class ControlSeverity(StrEnum):
    """Risk severity weight assigned to a ControlRequirement by the platform.

    Used for prioritisation in assessment workflows (Phase 2) and
    reporting.  Severity is platform-defined and never overridden
    per-organization in Phase 1.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@unique
class MappingConfidenceHint(StrEnum):
    """Confidence of a cross-framework ControlMapping relationship.

    HIGH    — the two controls share substantially the same requirement
              language and evidence expectations.
    MEDIUM  — significant overlap but each control has unique elements.
    LOW     — thematic similarity only; controls differ materially.

    In Phase 2, the AutoLinkingEngine will use these hints to decide
    whether to auto-confirm or require human review of suggested
    evidence links.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class PolicyThreshold:
    """Minimum passing percentage for a ControlRequirement in assessment.

    Stored as part of the platform-managed catalog definition.
    0-100 inclusive.
    """

    value: int

    def __post_init__(self) -> None:
        if not (0 <= self.value <= 100):
            raise ValueError(f"PolicyThreshold must be 0-100, got {self.value}")


@dataclass(frozen=True, slots=True)
class ControlMappingVersion:
    """Immutable version label for a ControlMapping revision.

    Format: "<major>.<minor>" — e.g. "1.0", "1.1".
    Incremented when mapping rationale or confidence changes.
    """

    major: int
    minor: int

    def __post_init__(self) -> None:
        if self.major < 1 or self.minor < 0:
            raise ValueError(
                f"ControlMappingVersion major must be ≥1 and minor ≥0, "
                f"got {self.major}.{self.minor}"
            )

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"

    @classmethod
    def initial(cls) -> ControlMappingVersion:
        return cls(major=1, minor=0)

    def bump_minor(self) -> ControlMappingVersion:
        return ControlMappingVersion(major=self.major, minor=self.minor + 1)


@dataclass(frozen=True, slots=True)
class FrameworkMetadata:
    """Immutable descriptor sourced from a FrameworkDefinitionPort adapter.

    All fields come directly from the adapter JSON; the domain never
    mutates them.
    """

    name: str
    version: str
    issuing_body: str
    description: str
    effective_date: str  # ISO 8601 date string — "2022-10-25"
    tags: tuple[str, ...]
    external_url: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkMetadata:
        return cls(
            name=data["name"],
            version=data["version"],
            issuing_body=data["issuing_body"],
            description=data["description"],
            effective_date=data["effective_date"],
            tags=tuple(data.get("tags", [])),
            external_url=data.get("external_url", ""),
        )
