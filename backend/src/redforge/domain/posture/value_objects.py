"""Value objects for the Security Posture bounded context.

All objects are immutable frozen dataclasses or StrEnums.

Naming conventions:
  - *Score: a float in [0.0, 1.0] representing vulnerability rate
  - *Rate: same (vulnerability rate)
  - Trend*: directional enums
  - *Policy: rule configuration (when to baseline, what counts as drift)
  - *Window: temporal scope definition
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum, unique
from typing import Any


@unique
class TrendDirection(StrEnum):
    """Direction of the vulnerability rate trend over a window.

    IMPROVING  — vulnerability rate decreasing over window
    DEGRADING  — vulnerability rate increasing over window
    STABLE     — rate within tolerance threshold
    NEW        — insufficient history to compute trend
    VOLATILE   — rate oscillating (standard deviation high)
    """

    IMPROVING = "improving"
    DEGRADING = "degrading"
    STABLE = "stable"
    NEW = "new"
    VOLATILE = "volatile"


@unique
class RegressionSeverity(StrEnum):
    """How severe a detected regression is."""

    CRITICAL = "critical"   # >= 20% increase in vulnerability rate
    HIGH = "high"           # >= 10% increase
    MEDIUM = "medium"       # >= 5% increase
    LOW = "low"             # >= 1% increase
    INFORMATIONAL = "informational"  # < 1% increase (rounding, noise)


@unique
class DriftType(StrEnum):
    """What category of configuration changed between snapshots."""

    MODEL = "model"
    PROVIDER = "provider"
    SYSTEM_PROMPT = "system_prompt"
    TOOL_CONFIGURATION = "tool_configuration"
    MCP_CONFIGURATION = "mcp_configuration"
    POLICY = "policy"
    CAPABILITIES = "capabilities"
    ATTACK_COVERAGE = "attack_coverage"
    EVALUATION_CONFIDENCE = "evaluation_confidence"


@unique
class BaselineStatus(StrEnum):
    """Lifecycle of a ValidationBaseline."""

    ACTIVE = "active"          # currently the reference point
    SUPERSEDED = "superseded"  # replaced by a newer baseline
    EXPIRED = "expired"        # age-based expiration
    REVOKED = "revoked"        # manually invalidated


@unique
class PostureLevel(StrEnum):
    """Aggregated security posture assessment.

    Computed from combined vulnerability rate across targets.
    """

    EXCELLENT = "excellent"    # vuln_rate < 0.05
    GOOD = "good"              # 0.05 <= vuln_rate < 0.15
    FAIR = "fair"              # 0.15 <= vuln_rate < 0.30
    POOR = "poor"              # 0.30 <= vuln_rate < 0.50
    CRITICAL = "critical"      # vuln_rate >= 0.50

    @classmethod
    def from_vulnerability_rate(cls, rate: float) -> PostureLevel:
        if rate < 0.05:
            return cls.EXCELLENT
        if rate < 0.15:
            return cls.GOOD
        if rate < 0.30:
            return cls.FAIR
        if rate < 0.50:
            return cls.POOR
        return cls.CRITICAL


@dataclass(frozen=True, slots=True)
class ValidationWindow:
    """Temporal scope for trend and posture computation.

    last_n_snapshots: if set, use the N most recent snapshots (overrides duration).
    min_snapshots: minimum required for trend to be valid (default 2).
    """

    duration: timedelta = timedelta(days=30)
    last_n_snapshots: int | None = None
    min_snapshots: int = 2

    def __post_init__(self) -> None:
        if self.last_n_snapshots is not None and self.last_n_snapshots < 1:
            raise ValueError("last_n_snapshots must be >= 1")
        if self.min_snapshots < 1:
            raise ValueError("min_snapshots must be >= 1")

    @classmethod
    def last_7_days(cls) -> ValidationWindow:
        return cls(duration=timedelta(days=7))

    @classmethod
    def last_30_days(cls) -> ValidationWindow:
        return cls(duration=timedelta(days=30))

    @classmethod
    def last_90_days(cls) -> ValidationWindow:
        return cls(duration=timedelta(days=90))

    @classmethod
    def last_n(cls, n: int) -> ValidationWindow:
        return cls(last_n_snapshots=n)


@dataclass(frozen=True, slots=True)
class BaselinePolicy:
    """Rules governing when and how a ValidationBaseline is established.

    auto_establish: if True, first completed snapshot becomes the baseline.
    stability_window: number of consecutive snapshots needed to auto-promote.
    stability_tolerance: max vulnerability-rate delta to consider "stable".
    max_age_days: baselines older than this are marked EXPIRED.
    require_minimum_attacks: do not baseline unless at least N attacks ran.
    """

    auto_establish: bool = True
    stability_window: int = 1
    stability_tolerance: float = 0.05
    max_age_days: int = 90
    require_minimum_attacks: int = 1

    def __post_init__(self) -> None:
        if self.stability_window < 1:
            raise ValueError("stability_window must be >= 1")
        if self.stability_tolerance < 0.0:
            raise ValueError("stability_tolerance must be >= 0.0")
        if self.max_age_days < 1:
            raise ValueError("max_age_days must be >= 1")
        if self.require_minimum_attacks < 1:
            raise ValueError("require_minimum_attacks must be >= 1")


@dataclass(frozen=True, slots=True)
class TrendPolicy:
    """Rules governing trend computation.

    degradation_threshold: vulnerability rate increase that triggers DEGRADING.
    improvement_threshold: vulnerability rate decrease that triggers IMPROVING.
    volatility_threshold: standard deviation above which trend is VOLATILE.
    min_snapshots_for_trend: minimum history depth before trend is computed.
    """

    degradation_threshold: float = 0.05
    improvement_threshold: float = 0.05
    volatility_threshold: float = 0.10
    min_snapshots_for_trend: int = 2

    def __post_init__(self) -> None:
        if self.degradation_threshold < 0.0:
            raise ValueError("degradation_threshold must be >= 0.0")
        if self.improvement_threshold < 0.0:
            raise ValueError("improvement_threshold must be >= 0.0")
        if self.volatility_threshold < 0.0:
            raise ValueError("volatility_threshold must be >= 0.0")
        if self.min_snapshots_for_trend < 2:
            raise ValueError("min_snapshots_for_trend must be >= 2")


@dataclass(frozen=True, slots=True)
class SnapshotMetrics:
    """Core security metrics extracted from one ValidationRun.

    vulnerability_rate: failed_attacks / total_attacks (0.0 = perfect, 1.0 = all failed)
    pass_rate: 1 - vulnerability_rate
    total_attacks: total number of attack steps executed
    finding_count: number of security findings generated
    critical_finding_count: subset with critical severity
    high_finding_count: subset with high severity
    mean_confidence: average classifier confidence across steps
    """

    vulnerability_rate: float
    total_attacks: int
    finding_count: int
    duration_ms: int
    pass_rate: float = 0.0
    critical_finding_count: int = 0
    high_finding_count: int = 0
    mean_confidence: float = 0.0

    def __post_init__(self) -> None:
        if self.vulnerability_rate < 0.0 or self.vulnerability_rate > 1.0:
            raise ValueError(f"vulnerability_rate must be 0.0-1.0, got {self.vulnerability_rate}")
        if self.total_attacks < 0:
            raise ValueError("total_attacks must be >= 0")
        if self.finding_count < 0:
            raise ValueError("finding_count must be >= 0")

    @property
    def has_critical_findings(self) -> bool:
        return self.critical_finding_count > 0

    @property
    def severity_weighted_rate(self) -> float:
        """Vulnerability rate amplified by critical/high finding proportion."""
        if self.finding_count == 0:
            return self.vulnerability_rate
        critical_weight = (self.critical_finding_count * 3.0 + self.high_finding_count * 2.0)
        amplifier = min(1.0 + critical_weight / (self.finding_count * 3.0), 2.0)
        return min(self.vulnerability_rate * amplifier, 1.0)


@dataclass(frozen=True, slots=True)
class ConfigurationFingerprint:
    """Snapshot of the target's configuration at validation time.

    Used for drift detection: compare fingerprints across snapshots to
    identify what changed between runs.

    system_prompt_hash: SHA-256 hex of the system prompt (first 64 chars shown).
    tool_names: sorted tuple of declared tool names.
    mcp_server_ids: sorted tuple of connected MCP server IDs.
    attack_categories: frozenset of attack categories tested.
    """

    model: str
    provider: str
    system_prompt_hash: str
    attack_categories: frozenset[str]
    tool_names: tuple[str, ...] = ()
    mcp_server_ids: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()

    def diff(self, other: ConfigurationFingerprint) -> list[DriftType]:
        """Return list of DriftTypes that changed from self to other."""
        changes: list[DriftType] = []
        if self.model != other.model:
            changes.append(DriftType.MODEL)
        if self.provider != other.provider:
            changes.append(DriftType.PROVIDER)
        if self.system_prompt_hash != other.system_prompt_hash:
            changes.append(DriftType.SYSTEM_PROMPT)
        if set(self.tool_names) != set(other.tool_names):
            changes.append(DriftType.TOOL_CONFIGURATION)
        if set(self.mcp_server_ids) != set(other.mcp_server_ids):
            changes.append(DriftType.MCP_CONFIGURATION)
        if set(self.capabilities) != set(other.capabilities):
            changes.append(DriftType.CAPABILITIES)
        if self.attack_categories != other.attack_categories:
            changes.append(DriftType.ATTACK_COVERAGE)
        return changes


@dataclass(frozen=True, slots=True)
class DriftEvent:
    """A detected configuration change between two snapshots.

    source_snapshot_id: earlier snapshot used as reference.
    target_snapshot_id: newer snapshot where the change was detected.
    drift_types: which dimensions changed.
    description: human-readable summary.
    """

    source_snapshot_id: str
    target_snapshot_id: str
    drift_types: tuple[DriftType, ...]
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_model_drift(self) -> bool:
        return DriftType.MODEL in self.drift_types

    @property
    def has_prompt_drift(self) -> bool:
        return DriftType.SYSTEM_PROMPT in self.drift_types

    @property
    def is_significant(self) -> bool:
        """True when model, provider, or prompt changed."""
        significant = {DriftType.MODEL, DriftType.PROVIDER, DriftType.SYSTEM_PROMPT}
        return bool(set(self.drift_types) & significant)


@dataclass(frozen=True, slots=True)
class ValidationRegressionDetail:
    """Detail of a detected regression.

    baseline_snapshot_id: reference snapshot.
    current_snapshot_id: snapshot that exceeded the baseline.
    vulnerability_rate_delta: current_rate - baseline_rate (positive = worse).
    new_finding_count: net new findings vs baseline.
    severity: computed regression severity.
    """

    baseline_snapshot_id: str
    current_snapshot_id: str
    vulnerability_rate_delta: float
    new_finding_count: int
    severity: RegressionSeverity
    description: str

    @property
    def is_regression(self) -> bool:
        return self.vulnerability_rate_delta > 0

    @property
    def is_improvement(self) -> bool:
        return self.vulnerability_rate_delta < 0


@dataclass(frozen=True, slots=True)
class ValidationTrend:
    """Computed trend over a ValidationHistory window.

    direction: overall direction across the window.
    first_rate: vulnerability rate at start of window.
    last_rate: vulnerability rate at end of window.
    delta: last_rate - first_rate.
    snapshot_count: number of snapshots included in computation.
    std_dev: standard deviation of rates across the window.
    """

    direction: TrendDirection
    first_rate: float
    last_rate: float
    delta: float
    snapshot_count: int
    std_dev: float
    window: ValidationWindow

    @property
    def is_improving(self) -> bool:
        return self.direction == TrendDirection.IMPROVING

    @property
    def is_degrading(self) -> bool:
        return self.direction == TrendDirection.DEGRADING


@dataclass(frozen=True, slots=True)
class SecurityPostureScore:
    """Aggregate security posture across an organization or target set.

    mean_vulnerability_rate: average across all included snapshots.
    level: PostureLevel derived from mean rate.
    targets_assessed: number of distinct targets included.
    total_findings: sum of finding counts.
    critical_targets: targets with critical posture level.
    trend: overall direction across the portfolio.
    """

    mean_vulnerability_rate: float
    level: PostureLevel
    targets_assessed: int
    total_findings: int
    critical_targets: int
    trend: TrendDirection
    snapshot_count: int

    def __post_init__(self) -> None:
        if self.mean_vulnerability_rate < 0.0 or self.mean_vulnerability_rate > 1.0:
            raise ValueError("mean_vulnerability_rate must be 0.0-1.0")

    @property
    def has_critical_targets(self) -> bool:
        return self.critical_targets > 0
