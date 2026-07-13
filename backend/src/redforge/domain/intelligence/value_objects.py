"""Value objects for the AI Security Intelligence bounded context.

All objects are immutable frozen dataclasses or StrEnums.
No external bounded context imports — attack categories are str values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import Any


@unique
class RecommendationPriority(StrEnum):
    """Priority of a security recommendation.

    Distinct from RiskPriority (which is per-incident).
    Recommendations aggregate across multiple incidents and posture signals.
    """

    CRITICAL = "critical"   # immediate action required; system may be actively exploitable
    HIGH = "high"           # action within 24-72 hours
    MEDIUM = "medium"       # action within 2 weeks
    LOW = "low"             # action within 90 days; improvement opportunity


@unique
class RecommendationCategory(StrEnum):
    """Semantic category of a recommendation.

    Drives remediation plan selection and KG relationship type.
    """

    CRITICAL_SECURITY_RISK = "critical_security_risk"
    COVERAGE_GAP = "coverage_gap"
    PROMPT_SECURITY = "prompt_security"
    AGENT_SECURITY = "agent_security"
    TOOL_SECURITY = "tool_security"
    MCP_SECURITY = "mcp_security"
    MEMORY_SECURITY = "memory_security"
    RAG_SECURITY = "rag_security"
    PROVIDER_SECURITY = "provider_security"
    MODEL_UPGRADE = "model_upgrade"
    CONFIGURATION_DRIFT = "configuration_drift"
    POLICY_WEAKNESS = "policy_weakness"
    OPERATIONAL_IMPROVEMENT = "operational_improvement"
    COMPLIANCE_GAP = "compliance_gap"


@unique
class InsightType(StrEnum):
    """Type of security insight detected."""

    PATTERN = "pattern"              # recurring attack pattern across targets or time
    ANOMALY = "anomaly"              # unexpected deviation from baseline
    TREND = "trend"                  # directional change in vulnerability rate
    CORRELATION = "correlation"      # related attack vectors succeeding together
    COVERAGE = "coverage"            # gap in attack category coverage
    REGRESSION = "regression"        # unexplained security degradation


@unique
class GapType(StrEnum):
    """What kind of security gap was identified."""

    ATTACK_COVERAGE = "attack_coverage"      # untested attack categories
    PROVIDER_COVERAGE = "provider_coverage"  # providers not validated
    TARGET_COVERAGE = "target_coverage"      # targets with no recent validation
    TEMPORAL_COVERAGE = "temporal_coverage"  # targets not validated within policy window


@unique
class RecommendationStatus(StrEnum):
    """Lifecycle state of a Recommendation."""

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    IMPLEMENTED = "implemented"
    DISMISSED = "dismissed"


@unique
class RemediationEffort(StrEnum):
    """Estimated effort to implement a remediation step."""

    IMMEDIATE = "immediate"      # < 1 hour; config change or emergency response
    SHORT_TERM = "short_term"    # 1-3 days; targeted fix or hotfix
    MEDIUM_TERM = "medium_term"  # 1-2 weeks; structured remediation
    LONG_TERM = "long_term"      # 1-3 months; architectural change


@dataclass(frozen=True, slots=True)
class RemediationStep:
    """A single concrete remediation action.

    order: 1-based execution order within the RemediationPlan.
    automation_available: True if this step can be scripted or triggered by RedForge.
    """

    order: int
    title: str
    description: str
    effort: RemediationEffort
    automation_available: bool = False
    reference_url: str = ""


@dataclass(frozen=True, slots=True)
class RecommendationEvidence:
    """Evidence supporting a Recommendation.

    All IDs are references (strings), not domain entities — keeps this
    bounded context decoupled from findings/evidence/risk bounded contexts.

    rationale: human-readable explanation of why this evidence supports the recommendation.
    """

    finding_ids: tuple[str, ...] = ()
    risk_incident_ids: tuple[str, ...] = ()
    evidence_chain_ids: tuple[str, ...] = ()
    snapshot_ids: tuple[str, ...] = ()
    insight_ids: tuple[str, ...] = ()
    rationale: str = ""

    @property
    def total_references(self) -> int:
        return (
            len(self.finding_ids)
            + len(self.risk_incident_ids)
            + len(self.evidence_chain_ids)
            + len(self.snapshot_ids)
        )

    @property
    def is_well_supported(self) -> bool:
        """True when at least two independent evidence sources corroborate."""
        non_empty = sum(
            1
            for src in (
                self.finding_ids,
                self.risk_incident_ids,
                self.evidence_chain_ids,
                self.snapshot_ids,
            )
            if src
        )
        return non_empty >= 2


@dataclass(frozen=True, slots=True)
class AttackCoverageGap:
    """A gap in the attack category coverage for one target.

    tested_categories: attack categories that have been executed.
    missing_categories: attack categories that have NEVER been executed.
    coverage_rate: tested / total (0.0 = no coverage, 1.0 = full coverage).
    """

    target_id: str
    organization_id: str
    tested_categories: frozenset[str]
    missing_categories: frozenset[str]
    coverage_rate: float
    days_since_last_validation: int | None = None

    @property
    def total_categories(self) -> int:
        return len(self.tested_categories) + len(self.missing_categories)

    @property
    def gap_severity(self) -> RecommendationPriority:
        if self.coverage_rate < 0.25:
            return RecommendationPriority.CRITICAL
        if self.coverage_rate < 0.50:
            return RecommendationPriority.HIGH
        if self.coverage_rate < 0.75:
            return RecommendationPriority.MEDIUM
        return RecommendationPriority.LOW


@dataclass(frozen=True, slots=True)
class SecurityGap:
    """A structural security gap not captured by coverage rate alone.

    gap_type: which dimension is missing.
    affected_targets: target IDs impacted by this gap.
    severity: computed gap severity.
    """

    gap_type: GapType
    description: str
    affected_targets: tuple[str, ...]
    severity: RecommendationPriority
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def affects_multiple_targets(self) -> bool:
        return len(self.affected_targets) > 1


@dataclass(frozen=True, slots=True)
class SecurityTrend:
    """A directional change in a security metric over a time period.

    metric: which security dimension is trending (e.g. "vulnerability_rate").
    direction: "improving" / "degrading" / "stable" / "volatile"
    delta: absolute change in the metric over the period.
    description: human-readable summary of the trend.
    """

    metric: str
    direction: str
    period_days: int
    delta: float
    snapshot_count: int
    description: str


@dataclass(frozen=True, slots=True)
class RiskNarrative:
    """Human-readable narrative summarizing the risk posture.

    Constructed deterministically from risk signals — NOT LLM-generated.
    summary: 1-2 sentence executive summary.
    key_risks: ordered list of the most significant risk descriptions.
    trend_description: one sentence on the directional trend.
    recommendations_summary: one sentence on top recommended actions.
    """

    summary: str
    key_risks: tuple[str, ...]
    trend_description: str
    recommendations_summary: str
    critical_incident_count: int = 0
    high_incident_count: int = 0


@dataclass(frozen=True, slots=True)
class PostureNarrative:
    """Human-readable narrative summarizing the security posture.

    Constructed deterministically — NOT LLM-generated.
    overall_level: PostureLevel value (str).
    trend_summary: one sentence on direction.
    critical_targets: target IDs at critical level.
    improvement_areas: ordered list of areas needing attention.
    """

    overall_level: str
    trend_summary: str
    targets_assessed: int
    critical_targets: tuple[str, ...]
    improvement_areas: tuple[str, ...]
    mean_vulnerability_rate: float


@dataclass(frozen=True, slots=True)
class RecommendationRule:
    """Descriptor for a recommendation rule.

    rule_id: unique identifier (kebab-case).
    name: human-readable name.
    category: which RecommendationCategory this rule produces.
    priority: default priority (can be overridden by PriorityEngine).
    condition_description: plain-English description of when this rule fires.
    """

    rule_id: str
    name: str
    category: RecommendationCategory
    default_priority: RecommendationPriority
    condition_description: str
    version: str = "1.0"
