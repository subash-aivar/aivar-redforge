"""Value objects for M26 Phase 7 Cloud Risk Correlation Engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Self, cast
from uuid import UUID, uuid4


def _as_float(value: object, default: float = 0.0) -> float:
    if value is None:
        return default
    return float(cast("str | float | int", value))


def _as_int(value: object, default: int = 0) -> int:
    if value is None:
        return default
    return int(cast("str | float | int", value))


@unique
class RiskCategory(StrEnum):
    CONFIGURATION = "CONFIGURATION"
    IDENTITY = "IDENTITY"
    EXPOSURE = "EXPOSURE"
    RUNTIME = "RUNTIME"
    COMPLIANCE = "COMPLIANCE"
    KUBERNETES = "KUBERNETES"
    BUSINESS_CRITICALITY = "BUSINESS_CRITICALITY"
    INTERNET_EXPOSURE = "INTERNET_EXPOSURE"
    ENCRYPTION = "ENCRYPTION"
    PRIVILEGE = "PRIVILEGE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PUBLIC_ACCESSIBILITY = "PUBLIC_ACCESSIBILITY"
    THREAT_INTEL = "THREAT_INTEL"
    ATTACK_PATH = "ATTACK_PATH"  # metadata-only stub — no path analysis
    COMPOSITE = "COMPOSITE"


@unique
class RiskSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@unique
class RiskConfidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


@unique
class RiskTrend(StrEnum):
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    WORSENING = "WORSENING"
    UNKNOWN = "UNKNOWN"


@unique
class RiskState(StrEnum):
    ACTIVE = "ACTIVE"
    SUPPRESSED = "SUPPRESSED"
    REOPENED = "REOPENED"
    EXPIRED = "EXPIRED"


@unique
class RiskSource(StrEnum):
    CSPM = "CSPM"
    IDENTITY = "IDENTITY"
    KUBERNETES = "KUBERNETES"
    RUNTIME = "RUNTIME"
    COMPLIANCE = "COMPLIANCE"
    INVENTORY = "INVENTORY"
    THREAT_INTEL = "THREAT_INTEL"
    EXPOSURE = "EXPOSURE"
    MANUAL = "MANUAL"
    COMPOSITE = "COMPOSITE"


@dataclass(frozen=True, slots=True)
class RiskScore:
    """Normalized risk score 0.0-10.0 (higher = worse)."""

    value: float

    def __post_init__(self) -> None:
        if self.value < 0.0 or self.value > 10.0:
            raise ValueError("RiskScore.value must be 0.0..10.0")

    def to_severity(self) -> RiskSeverity:
        if self.value >= 9.0:
            return RiskSeverity.CRITICAL
        if self.value >= 7.0:
            return RiskSeverity.HIGH
        if self.value >= 4.0:
            return RiskSeverity.MEDIUM
        if self.value >= 1.0:
            return RiskSeverity.LOW
        return RiskSeverity.INFO

    @classmethod
    def clamp(cls, raw: float) -> Self:
        return cls(max(0.0, min(10.0, float(raw))))


@dataclass(frozen=True, slots=True)
class RiskCalculationVersion:
    major: int
    minor: int
    patch: int
    profile: str = "default"

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("version parts must be >= 0")
        if not self.profile or len(self.profile) > 64:
            raise ValueError("profile invalid")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}+{self.profile}"

    def to_dict(self) -> dict[str, object]:
        return {
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "profile": self.profile,
            "label": str(self),
        }

    @classmethod
    def default(cls) -> Self:
        return cls(major=1, minor=0, patch=0, profile="default")

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls.default()
        return cls(
            major=_as_int(data.get("major"), 1) or 1,
            minor=_as_int(data.get("minor"), 0),
            patch=_as_int(data.get("patch"), 0),
            profile=str(data.get("profile", "default")),
        )


@dataclass(frozen=True, slots=True)
class CloudRiskScoreId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> Self:
        return cls(UUID(raw))


@dataclass(frozen=True, slots=True)
class RiskWeightProfile:
    """Configurable dimension weights — must sum to 1.0 (±1e-6)."""

    threat_intel: float = 0.20
    compliance: float = 0.15
    identity: float = 0.20
    exposure: float = 0.15
    attack_path: float = 0.0  # metadata stub — weight redistributed by default
    cspm: float = 0.15
    criticality: float = 0.05
    kubernetes: float = 0.05
    runtime: float = 0.05

    def __post_init__(self) -> None:
        total = (
            self.threat_intel
            + self.compliance
            + self.identity
            + self.exposure
            + self.attack_path
            + self.cspm
            + self.criticality
            + self.kubernetes
            + self.runtime
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"RiskWeightProfile weights must sum to 1.0 (got {total})")
        for name, value in self.to_dict().items():
            if float(value) < 0.0 or float(value) > 1.0:
                raise ValueError(f"weight {name} out of range")

    def to_dict(self) -> dict[str, float]:
        return {
            "threat_intel": self.threat_intel,
            "compliance": self.compliance,
            "identity": self.identity,
            "exposure": self.exposure,
            "attack_path": self.attack_path,
            "cspm": self.cspm,
            "criticality": self.criticality,
            "kubernetes": self.kubernetes,
            "runtime": self.runtime,
        }

    @classmethod
    def default(cls) -> Self:
        # Freeze defaults with attack_path=0.15 replaced: CSPM+0.05, runtime+0.05, k8s+0.05
        # (no attack-path analysis in Phase 7 — weight redistributed)
        return cls(
            threat_intel=0.20,
            compliance=0.15,
            identity=0.20,
            exposure=0.15,
            attack_path=0.0,
            cspm=0.15,
            criticality=0.05,
            kubernetes=0.05,
            runtime=0.05,
        )

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls.default()
        return cls(
            threat_intel=_as_float(data.get("threat_intel"), 0.20),
            compliance=_as_float(data.get("compliance"), 0.15),
            identity=_as_float(data.get("identity"), 0.20),
            exposure=_as_float(data.get("exposure"), 0.15),
            attack_path=_as_float(data.get("attack_path"), 0.0),
            cspm=_as_float(data.get("cspm"), 0.15),
            criticality=_as_float(data.get("criticality"), 0.05),
            kubernetes=_as_float(data.get("kubernetes"), 0.05),
            runtime=_as_float(data.get("runtime"), 0.05),
        )


@dataclass(frozen=True, slots=True)
class RiskDimensionScores:
    threat_intel: float = 0.0
    compliance: float = 0.0
    identity: float = 0.0
    exposure: float = 0.0
    attack_path: float = 0.0
    cspm: float = 0.0
    criticality: float = 0.0
    kubernetes: float = 0.0
    runtime: float = 0.0

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if value < 0.0 or value > 10.0:
                raise ValueError(f"dimension {name} must be 0..10")

    def to_dict(self) -> dict[str, float]:
        return {
            "threat_intel": self.threat_intel,
            "compliance": self.compliance,
            "identity": self.identity,
            "exposure": self.exposure,
            "attack_path": self.attack_path,
            "cspm": self.cspm,
            "criticality": self.criticality,
            "kubernetes": self.kubernetes,
            "runtime": self.runtime,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls()
        return cls(**{k: _as_float(data.get(k), 0.0) for k in cls().to_dict()})


def severity_to_score(severity: str) -> float:
    mapping = {
        "CRITICAL": 10.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "INFO": 0.5,
    }
    return mapping.get(severity.upper(), 0.0)


def compute_weighted_overall(
    dimensions: RiskDimensionScores,
    weights: RiskWeightProfile,
) -> RiskScore:
    d = dimensions.to_dict()
    w = weights.to_dict()
    raw = sum(d[k] * w[k] for k in w)
    return RiskScore.clamp(raw)
