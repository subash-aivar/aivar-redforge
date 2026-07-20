"""Value objects for M26 Phase 4 CSPM."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, unique
from typing import Self
from uuid import UUID, uuid4


@unique
class FindingSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@unique
class FindingStatus(StrEnum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    SUPPRESSED = "SUPPRESSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    EXPIRED = "EXPIRED"


@unique
class FindingConfidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


@unique
class EvaluationStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


@unique
class DriftKind(StrEnum):
    CONFIGURATION = "CONFIGURATION"
    POLICY = "POLICY"
    COMPLIANCE = "COMPLIANCE"


@dataclass(frozen=True, slots=True)
class CSPMFindingId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("CSPMFindingId.value must be UUID")

    @classmethod
    def generate(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(UUID(raw))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CSPMPolicyId:
    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("CSPMPolicyId required")
        if len(self.value) > 128:
            raise ValueError("CSPMPolicyId max 128 chars")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CSPMRuleId:
    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("CSPMRuleId required")
        if len(self.value) > 128:
            raise ValueError("CSPMRuleId max 128 chars")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CSPMEvaluationId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("CSPMEvaluationId.value must be UUID")

    @classmethod
    def generate(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(UUID(raw))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PolicyVersion:
    major: int
    minor: int
    patch: int = 0

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("PolicyVersion components must be >= 0")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @classmethod
    def parse(cls, raw: str) -> Self:
        parts = raw.strip().split(".")
        if len(parts) not in (2, 3):
            raise ValueError(f"Invalid PolicyVersion: {raw}")
        major, minor = int(parts[0]), int(parts[1])
        patch = int(parts[2]) if len(parts) == 3 else 0
        return cls(major=major, minor=minor, patch=patch)

    def to_dict(self) -> dict[str, int]:
        return {"major": self.major, "minor": self.minor, "patch": self.patch}


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    category: str
    tags: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    required_permissions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.category or len(self.category) > 128:
            raise ValueError("RuleMetadata.category invalid")
        if self.cvss_score is not None and not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError("cvss_score must be 0.0-10.0")

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "tags": list(self.tags),
            "mitre_techniques": list(self.mitre_techniques),
            "cwe_ids": list(self.cwe_ids),
            "cvss_score": self.cvss_score,
            "required_permissions": list(self.required_permissions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Self:
        def _str_tuple(key: str) -> tuple[str, ...]:
            raw = data.get(key) or []
            if not isinstance(raw, (list, tuple)):
                return ()
            return tuple(str(x) for x in raw)

        cvss_raw = data.get("cvss_score")
        cvss: float | None
        if cvss_raw is None:
            cvss = None
        elif isinstance(cvss_raw, (int, float, str)):
            cvss = float(cvss_raw)
        else:
            cvss = None

        return cls(
            category=str(data.get("category", "general")),
            tags=_str_tuple("tags"),
            mitre_techniques=_str_tuple("mitre_techniques"),
            cwe_ids=_str_tuple("cwe_ids"),
            cvss_score=cvss,
            required_permissions=_str_tuple("required_permissions"),
        )


@dataclass(frozen=True, slots=True)
class ComplianceRef:
    """Pointer into M24 catalog — framework_key + requirement_ref."""

    framework_key: str
    requirement_ref: str
    resolved: bool = False

    def __post_init__(self) -> None:
        if not self.framework_key or len(self.framework_key) > 64:
            raise ValueError("ComplianceRef.framework_key invalid")
        if not self.requirement_ref or len(self.requirement_ref) > 128:
            raise ValueError("ComplianceRef.requirement_ref invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "framework_key": self.framework_key,
            "requirement_ref": self.requirement_ref,
            "resolved": self.resolved,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Self:
        return cls(
            framework_key=str(data["framework_key"]),
            requirement_ref=str(data["requirement_ref"]),
            resolved=bool(data.get("resolved", False)),
        )


@dataclass(frozen=True, slots=True)
class ComplianceCoverage:
    mapped_frameworks: tuple[str, ...]
    mapped_controls: int
    unresolved_refs: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "mapped_frameworks": list(self.mapped_frameworks),
            "mapped_controls": self.mapped_controls,
            "unresolved_refs": self.unresolved_refs,
        }


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    """Provider-agnostic evaluation input built from CloudAsset."""

    cloud_asset_id: str
    organization_id: str
    cloud_account_id: str
    asset_type: str
    provider_type: str
    provider_id: str
    display_name: str
    region_code: str
    tags: dict[str, str]
    normalized_config: dict[str, object]
    config_hash: str
    captured_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "cloud_asset_id": self.cloud_asset_id,
            "organization_id": self.organization_id,
            "cloud_account_id": self.cloud_account_id,
            "asset_type": self.asset_type,
            "provider_type": self.provider_type,
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "region_code": self.region_code,
            "tags": dict(self.tags),
            "normalized_config": dict(self.normalized_config),
            "config_hash": self.config_hash,
            "captured_at": self.captured_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    organization_id: str
    cloud_account_id: str | None
    evaluation_id: str
    triggered_by: str
    incremental: bool = False
    policy_ids: tuple[str, ...] = ()
    started_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "organization_id": self.organization_id,
            "cloud_account_id": self.cloud_account_id,
            "evaluation_id": self.evaluation_id,
            "triggered_by": self.triggered_by,
            "incremental": self.incremental,
            "policy_ids": list(self.policy_ids),
            "started_at": self.started_at.isoformat() if self.started_at else None,
        }
