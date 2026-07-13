"""Risk Correlation Engine — Enterprise Risk Incident Production.

Consumes Findings, Evidence Chains, Validation Results, and Attack Chains
to produce correlated Risk Incidents with CVSS-inspired scoring.

This module lives in the Application layer. It does NOT modify Domain entities,
Pipeline, Scheduler, or Provider infrastructure. It is pure orchestration logic
that correlates existing data into actionable risk assessments.

────────────────────────────────────────────────────────────────────────────────
ARCHITECTURE REVIEW
────────────────────────────────────────────────────────────────────────────────

Q: Can risk scoring evolve independently?
A: Yes. RiskScoreCalculator is a Protocol. The default implementation uses
   CVSS-inspired heuristics, but any implementation satisfying the protocol
   can be injected at composition time without touching correlation logic.

Q: Can customers replace the scoring algorithm?
A: Yes. Inject a custom RiskScoreCalculator implementation. The engine accepts
   it as a constructor parameter. Customers can weight factors differently,
   add industry-specific modifiers, or use entirely different methodologies.

Q: Can ML replace heuristics later?
A: Yes. The RiskScoreCalculator protocol accepts RiskFactor lists and returns
   a score. An ML model that consumes the same factors and emits a float
   score is a drop-in replacement. No engine changes required.

Q: Can risk feed executive reporting?
A: Yes. RiskIncident includes executive_summary, recommended_actions,
   affected_targets, priority, and trend data — all designed for
   executive dashboards and compliance reporting.

Q: Can incidents merge automatically?
A: Yes. RiskCorrelationEngine.merge_incidents() combines related incidents
   sharing targets or attack patterns. Scores are recalculated on merge.

Q: Can risk trends span months?
A: Yes. RiskHistory stores timestamped snapshots. RiskTrend computes
   direction over arbitrary windows. No time limit is imposed.

Q: Would Microsoft, CrowdStrike, Wiz, Palo Alto, and Anthropic build it
   similarly?
A: The architecture follows enterprise security product patterns:
   - Protocol-based scoring (replaceable algorithms)
   - Factor decomposition (CVSS-style multi-dimensional)
   - Correlation amplification (cross-validation, repeated targets)
   - Incident lifecycle (open → acknowledged → resolved)
   - Executive-ready outputs (summary, actions, affected assets)
   These patterns appear in Defender, Falcon, Wiz Issues, Cortex XSOAR,
   and align with how Anthropic structures safety evaluations.
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum, unique
from typing import Protocol, runtime_checkable

# ─── Enums ────────────────────────────────────────────────────────────────────


@unique
class RiskPriority(StrEnum):
    """Priority classification for a risk incident.

    Maps to operational urgency and SLA requirements.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@unique
class RiskTrend(StrEnum):
    """Directional trend of risk over time."""

    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"
    NEW = "new"


@unique
class IncidentStatus(StrEnum):
    """Lifecycle status of a risk incident."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


@unique
class RiskFactorType(StrEnum):
    """Categories of risk factors contributing to an incident score."""

    LIKELIHOOD = "likelihood"
    IMPACT = "impact"
    EXPLOITABILITY = "exploitability"
    BUSINESS_CRITICALITY = "business_criticality"
    CONFIDENCE = "confidence"
    EVIDENCE_STRENGTH = "evidence_strength"
    REPEATED_OCCURRENCE = "repeated_occurrence"
    CROSS_VALIDATION = "cross_validation"
    REPEATED_TARGET = "repeated_target"
    PROVIDER_RISK = "provider_risk"
    MODEL_SENSITIVITY = "model_sensitivity"


# ─── Value Objects ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """A single scored dimension contributing to overall risk.

    Each factor has a type, a normalized score (0.0-1.0), a weight
    that determines its influence, and a human-readable rationale.
    """

    factor_type: RiskFactorType
    score: float  # 0.0 - 1.0
    weight: float  # 0.0 - 1.0, relative importance
    rationale: str

    def __post_init__(self) -> None:
        if self.score < 0.0 or self.score > 1.0:
            raise ValueError(f"Factor score must be 0.0-1.0, got {self.score}")
        if self.weight < 0.0 or self.weight > 1.0:
            raise ValueError(f"Factor weight must be 0.0-1.0, got {self.weight}")

    @property
    def weighted_score(self) -> float:
        """Score multiplied by weight."""
        return self.score * self.weight


@dataclass(frozen=True, slots=True)
class RiskScore:
    """Composite risk score with factor decomposition.

    Overall score is 0.0-10.0 (CVSS-aligned scale).
    Factors provide transparency into how the score was derived.
    """

    overall: float  # 0.0 - 10.0
    factors: tuple[RiskFactor, ...]

    def __post_init__(self) -> None:
        if self.overall < 0.0 or self.overall > 10.0:
            raise ValueError(
                f"Overall risk score must be 0.0-10.0, got {self.overall}"
            )

    @property
    def priority(self) -> RiskPriority:
        """Derive priority from overall score."""
        if self.overall >= 9.0:
            return RiskPriority.CRITICAL
        if self.overall >= 7.0:
            return RiskPriority.HIGH
        if self.overall >= 4.0:
            return RiskPriority.MEDIUM
        if self.overall >= 1.0:
            return RiskPriority.LOW
        return RiskPriority.INFORMATIONAL


@dataclass(frozen=True, slots=True)
class RiskHistoryEntry:
    """A point-in-time snapshot of risk for an incident."""

    recorded_at: datetime
    score: float
    priority: RiskPriority
    event: str  # What caused the score change


@dataclass(slots=True)
class RiskHistory:
    """Time-series risk history for trend analysis.

    Stores snapshots to enable trend computation over arbitrary windows.
    """

    entries: list[RiskHistoryEntry] = field(default_factory=list)

    def add(self, score: float, priority: RiskPriority, event: str) -> None:
        """Record a new history point."""
        self.entries.append(
            RiskHistoryEntry(
                recorded_at=datetime.now(UTC),
                score=score,
                priority=priority,
                event=event,
            )
        )

    def trend(self, window: timedelta = timedelta(days=30)) -> RiskTrend:
        """Compute trend direction over the given time window."""
        if len(self.entries) < 2:
            return RiskTrend.NEW

        cutoff = datetime.now(UTC) - window
        recent = [e for e in self.entries if e.recorded_at >= cutoff]

        if len(recent) < 2:
            return RiskTrend.STABLE

        first_score = recent[0].score
        last_score = recent[-1].score
        delta = last_score - first_score

        if delta > 0.5:
            return RiskTrend.INCREASING
        if delta < -0.5:
            return RiskTrend.DECREASING
        return RiskTrend.STABLE

    @property
    def latest_score(self) -> float:
        """Most recent recorded score."""
        if not self.entries:
            return 0.0
        return self.entries[-1].score


# ─── Input DTOs ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FindingInput:
    """Lightweight finding view for risk correlation.

    Decouples the engine from the Finding aggregate.
    """

    finding_id: str
    target_id: str
    organization_id: str
    run_id: str
    severity: str  # critical/high/medium/low/informational
    risk_score: float  # 0.0-10.0
    title: str
    evidence_ids: list[str]
    attack_type: str = ""
    provider: str = ""
    model: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceChainInput:
    """Evidence chain (attack chain) for risk correlation."""

    chain_id: str
    evidence_ids: list[str]
    attack_ids: list[str]
    run_id: str
    target_id: str
    correlation_score: float
    summary: str
    timeline_start: datetime
    timeline_end: datetime


@dataclass(frozen=True, slots=True)
class ValidationResultInput:
    """Validation run result summary for risk correlation."""

    run_id: str
    target_id: str
    organization_id: str
    status: str  # completed/failed
    total_checks: int
    failed_checks: int
    passed_checks: int
    duration_ms: int


# ─── Risk Incident (Output) ───────────────────────────────────────────────────


@dataclass
class RiskIncident:
    """A correlated risk incident produced by the engine.

    Aggregates findings, evidence chains, and validation results into
    a single actionable risk assessment with executive-ready outputs.
    """

    incident_id: str
    organization_id: str
    risk_score: RiskScore
    priority: RiskPriority
    status: IncidentStatus
    title: str
    executive_summary: str
    recommended_actions: list[str]
    affected_targets: list[str]
    finding_ids: list[str]
    evidence_chain_ids: list[str]
    validation_run_ids: list[str]
    attack_types: list[str]
    trend: RiskTrend
    history: RiskHistory
    created_at: datetime
    updated_at: datetime

    @property
    def target_count(self) -> int:
        return len(self.affected_targets)

    @property
    def finding_count(self) -> int:
        return len(self.finding_ids)

    @property
    def severity_label(self) -> str:
        """Human-readable severity for reporting."""
        return self.priority.value.upper()


# ─── Risk Score Calculator Protocol ──────────────────────────────────────────


@runtime_checkable
class RiskScoreCalculator(Protocol):
    """Protocol for risk score calculation.

    Implementations receive decomposed factors and produce a final score.
    Customers can replace the default CVSS-inspired calculator with
    custom algorithms, ML models, or industry-specific methodologies.
    """

    def calculate(self, factors: list[RiskFactor]) -> RiskScore:
        """Calculate overall risk score from factors."""
        ...


# ─── Default Score Calculator ─────────────────────────────────────────────────


class DefaultRiskScoreCalculator:
    """CVSS-inspired weighted risk score calculator.

    Computes a 0.0-10.0 score from weighted risk factors.
    Supports amplification bonuses for cross-validation,
    repeated targets, and provider/model sensitivity.
    """

    def calculate(self, factors: list[RiskFactor]) -> RiskScore:
        """Calculate weighted composite score from factors.

        Algorithm:
        1. Sum weighted_score for all factors.
        2. Normalize to 0.0-10.0 scale.
        3. Apply ceiling at 10.0.
        """
        if not factors:
            return RiskScore(overall=0.0, factors=())

        total_weight = sum(f.weight for f in factors)
        if total_weight == 0:
            return RiskScore(overall=0.0, factors=tuple(factors))

        weighted_sum = sum(f.weighted_score for f in factors)
        # Normalize: weighted_sum / total_weight gives 0.0-1.0, scale to 10.0
        raw_score = (weighted_sum / total_weight) * 10.0
        clamped = min(10.0, max(0.0, round(raw_score, 2)))

        return RiskScore(overall=clamped, factors=tuple(factors))


# ─── Factor Extraction ────────────────────────────────────────────────────────


_SEVERITY_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
    "informational": 0.1,
}

_PROVIDER_RISK_WEIGHTS: dict[str, float] = {
    "openai": 0.7,
    "anthropic": 0.7,
    "google": 0.6,
    "azure": 0.6,
    "aws": 0.6,
    "meta": 0.5,
    "mistral": 0.5,
    "custom": 0.8,
}


def _severity_to_score(severity: str) -> float:
    """Convert severity string to normalized score."""
    return _SEVERITY_SCORES.get(severity.lower(), 0.3)


def _provider_risk(provider: str) -> float:
    """Provider-specific risk weight (higher = more critical if compromised)."""
    return _PROVIDER_RISK_WEIGHTS.get(provider.lower(), 0.5)


class RiskFactorExtractor:
    """Extracts risk factors from correlated inputs.

    Evaluates findings, evidence chains, and validation results
    to produce a comprehensive set of scored risk factors.
    """

    def extract(
        self,
        findings: list[FindingInput],
        chains: list[EvidenceChainInput],
        validations: list[ValidationResultInput],
    ) -> list[RiskFactor]:
        """Extract all risk factors from the correlated inputs."""
        factors: list[RiskFactor] = []

        factors.append(self._likelihood(findings, validations))
        factors.append(self._impact(findings))
        factors.append(self._exploitability(findings, chains))
        factors.append(self._business_criticality(findings))
        factors.append(self._confidence(findings, chains))
        factors.append(self._evidence_strength(findings, chains))
        factors.append(self._repeated_occurrence(findings))
        factors.append(self._cross_validation(chains, validations))
        factors.append(self._repeated_target(findings))
        factors.append(self._provider_risk_factor(findings))
        factors.append(self._model_sensitivity(findings))

        return factors

    def _likelihood(
        self,
        findings: list[FindingInput],
        validations: list[ValidationResultInput],
    ) -> RiskFactor:
        """Estimate likelihood based on failure rates."""
        if not validations:
            # Fall back to severity-based estimate
            avg_sev = self._average_severity(findings)
            return RiskFactor(
                factor_type=RiskFactorType.LIKELIHOOD,
                score=avg_sev,
                weight=0.9,
                rationale="Estimated from severity (no validation data)",
            )

        total_checks = sum(v.total_checks for v in validations)
        failed_checks = sum(v.failed_checks for v in validations)
        if total_checks == 0:
            return RiskFactor(
                factor_type=RiskFactorType.LIKELIHOOD,
                score=0.0,
                weight=0.9,
                rationale="No checks executed",
            )

        failure_rate = failed_checks / total_checks
        return RiskFactor(
            factor_type=RiskFactorType.LIKELIHOOD,
            score=min(1.0, failure_rate * 1.2),  # Slight amplification
            weight=0.9,
            rationale=f"Failure rate: {failed_checks}/{total_checks} ({failure_rate:.0%})",
        )

    def _impact(self, findings: list[FindingInput]) -> RiskFactor:
        """Estimate impact from finding severity distribution."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.IMPACT,
                score=0.0,
                weight=1.0,
                rationale="No findings",
            )

        max_severity = max(_severity_to_score(f.severity) for f in findings)
        avg_severity = self._average_severity(findings)
        # Impact biased toward maximum severity (worst case matters)
        score = 0.7 * max_severity + 0.3 * avg_severity
        return RiskFactor(
            factor_type=RiskFactorType.IMPACT,
            score=min(1.0, score),
            weight=1.0,
            rationale=f"Max severity: {max_severity:.1f}, avg: {avg_severity:.1f}",
        )

    def _exploitability(
        self,
        findings: list[FindingInput],
        chains: list[EvidenceChainInput],
    ) -> RiskFactor:
        """Estimate exploitability from chain completeness and correlation."""
        if not chains:
            # No chains = isolated findings, lower exploitability
            return RiskFactor(
                factor_type=RiskFactorType.EXPLOITABILITY,
                score=0.3,
                weight=0.8,
                rationale="No attack chains detected (isolated findings)",
            )

        # Multi-step chains indicate higher exploitability
        avg_chain_len = sum(len(c.evidence_ids) for c in chains) / len(chains)
        avg_correlation = sum(c.correlation_score for c in chains) / len(chains)
        score = min(1.0, (avg_chain_len / 5.0) * 0.5 + avg_correlation * 0.5)
        return RiskFactor(
            factor_type=RiskFactorType.EXPLOITABILITY,
            score=score,
            weight=0.8,
            rationale=(
                f"Avg chain length: {avg_chain_len:.1f}, "
                f"avg correlation: {avg_correlation:.2f}"
            ),
        )

    def _business_criticality(self, findings: list[FindingInput]) -> RiskFactor:
        """Estimate business criticality from target diversity."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.BUSINESS_CRITICALITY,
                score=0.0,
                weight=0.7,
                rationale="No findings",
            )

        unique_targets = len({f.target_id for f in findings})
        # More targets affected = higher business criticality
        score = min(1.0, unique_targets * 0.25)
        return RiskFactor(
            factor_type=RiskFactorType.BUSINESS_CRITICALITY,
            score=score,
            weight=0.7,
            rationale=f"{unique_targets} unique target(s) affected",
        )

    def _confidence(
        self,
        findings: list[FindingInput],
        chains: list[EvidenceChainInput],
    ) -> RiskFactor:
        """Confidence in the risk assessment based on evidence quality."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.CONFIDENCE,
                score=0.0,
                weight=0.6,
                rationale="No findings to assess",
            )

        # More evidence chains = higher confidence
        chain_bonus = min(0.3, len(chains) * 0.1)
        # More findings = higher confidence
        finding_bonus = min(0.4, len(findings) * 0.05)
        base = 0.3  # Base confidence for any finding
        score = min(1.0, base + chain_bonus + finding_bonus)
        return RiskFactor(
            factor_type=RiskFactorType.CONFIDENCE,
            score=score,
            weight=0.6,
            rationale=(
                f"{len(findings)} finding(s), {len(chains)} chain(s)"
            ),
        )

    def _evidence_strength(
        self,
        findings: list[FindingInput],
        chains: list[EvidenceChainInput],
    ) -> RiskFactor:
        """Strength of supporting evidence."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.EVIDENCE_STRENGTH,
                score=0.0,
                weight=0.7,
                rationale="No evidence",
            )

        total_evidence = sum(len(f.evidence_ids) for f in findings)
        # More evidence supporting findings = stronger case
        score = min(1.0, total_evidence * 0.1)
        avg_chain_score = (
            sum(c.correlation_score for c in chains) / len(chains)
            if chains
            else 0.0
        )
        combined = score * 0.6 + avg_chain_score * 0.4
        return RiskFactor(
            factor_type=RiskFactorType.EVIDENCE_STRENGTH,
            score=min(1.0, combined),
            weight=0.7,
            rationale=f"{total_evidence} evidence record(s) across findings",
        )

    def _repeated_occurrence(self, findings: list[FindingInput]) -> RiskFactor:
        """Amplification for repeated attack patterns."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.REPEATED_OCCURRENCE,
                score=0.0,
                weight=0.6,
                rationale="No findings",
            )

        # Group by attack_type
        attack_counts: dict[str, int] = {}
        for f in findings:
            key = f.attack_type or "unknown"
            attack_counts[key] = attack_counts.get(key, 0) + 1

        max_repeats = max(attack_counts.values()) if attack_counts else 0
        # Amplify: repeated attacks indicate persistent threat
        score = min(1.0, (max_repeats - 1) * 0.2) if max_repeats > 1 else 0.0
        return RiskFactor(
            factor_type=RiskFactorType.REPEATED_OCCURRENCE,
            score=score,
            weight=0.6,
            rationale=f"Max repetitions of single attack type: {max_repeats}",
        )

    def _cross_validation(
        self,
        chains: list[EvidenceChainInput],
        validations: list[ValidationResultInput],
    ) -> RiskFactor:
        """Amplification when multiple validation runs confirm the same issue."""
        unique_runs = {c.run_id for c in chains} | {v.run_id for v in validations}
        if len(unique_runs) <= 1:
            return RiskFactor(
                factor_type=RiskFactorType.CROSS_VALIDATION,
                score=0.0,
                weight=0.5,
                rationale="Single validation run (no cross-validation)",
            )

        # Multiple runs confirming = amplification
        score = min(1.0, (len(unique_runs) - 1) * 0.25)
        return RiskFactor(
            factor_type=RiskFactorType.CROSS_VALIDATION,
            score=score,
            weight=0.5,
            rationale=f"{len(unique_runs)} validation runs confirm findings",
        )

    def _repeated_target(self, findings: list[FindingInput]) -> RiskFactor:
        """Amplification when the same target is attacked repeatedly."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.REPEATED_TARGET,
                score=0.0,
                weight=0.5,
                rationale="No findings",
            )

        target_counts: dict[str, int] = {}
        for f in findings:
            target_counts[f.target_id] = target_counts.get(f.target_id, 0) + 1

        max_target_hits = max(target_counts.values()) if target_counts else 0
        score = min(1.0, (max_target_hits - 1) * 0.15) if max_target_hits > 1 else 0.0
        return RiskFactor(
            factor_type=RiskFactorType.REPEATED_TARGET,
            score=score,
            weight=0.5,
            rationale=f"Most-attacked target hit {max_target_hits} time(s)",
        )

    def _provider_risk_factor(self, findings: list[FindingInput]) -> RiskFactor:
        """Provider-specific risk weighting."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.PROVIDER_RISK,
                score=0.0,
                weight=0.4,
                rationale="No findings",
            )

        providers = [f.provider for f in findings if f.provider]
        if not providers:
            return RiskFactor(
                factor_type=RiskFactorType.PROVIDER_RISK,
                score=0.5,
                weight=0.4,
                rationale="Provider not specified",
            )

        max_risk = max(_provider_risk(p) for p in providers)
        return RiskFactor(
            factor_type=RiskFactorType.PROVIDER_RISK,
            score=max_risk,
            weight=0.4,
            rationale=f"Highest provider risk: {max_risk:.1f} ({providers[0]})",
        )

    def _model_sensitivity(self, findings: list[FindingInput]) -> RiskFactor:
        """Model sensitivity weighting — newer/larger models carry more risk."""
        if not findings:
            return RiskFactor(
                factor_type=RiskFactorType.MODEL_SENSITIVITY,
                score=0.0,
                weight=0.3,
                rationale="No findings",
            )

        models = [f.model for f in findings if f.model]
        if not models:
            return RiskFactor(
                factor_type=RiskFactorType.MODEL_SENSITIVITY,
                score=0.5,
                weight=0.3,
                rationale="Model not specified (default sensitivity)",
            )

        # Heuristic: production models with "gpt-4", "claude", "gemini" = higher
        high_sensitivity = any(
            any(k in m.lower() for k in ("gpt-4", "claude-3", "gemini"))
            for m in models
        )
        score = 0.8 if high_sensitivity else 0.4
        return RiskFactor(
            factor_type=RiskFactorType.MODEL_SENSITIVITY,
            score=score,
            weight=0.3,
            rationale=f"Models: {', '.join(sorted(set(models))[:3])}",
        )

    def _average_severity(self, findings: list[FindingInput]) -> float:
        """Compute average severity score across findings."""
        if not findings:
            return 0.0
        return sum(_severity_to_score(f.severity) for f in findings) / len(findings)


# ─── Summary Generation ───────────────────────────────────────────────────────


def _generate_executive_summary(
    findings: list[FindingInput],
    chains: list[EvidenceChainInput],
    score: RiskScore,
) -> str:
    """Generate a concise executive summary for the incident."""
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    targets = len({f.target_id for f in findings})
    attack_types = len({f.attack_type for f in findings if f.attack_type})

    parts = [
        f"Risk Score: {score.overall:.1f}/10.0 ({score.priority.value.upper()}).",
        f"{len(findings)} finding(s) across {targets} target(s).",
    ]

    if chains:
        parts.append(f"{len(chains)} correlated attack chain(s) detected.")

    if attack_types:
        parts.append(f"{attack_types} distinct attack type(s) observed.")

    # Severity breakdown
    sev_parts = []
    for sev in ("critical", "high", "medium", "low"):
        count = severity_counts.get(sev, 0)
        if count:
            sev_parts.append(f"{count} {sev}")
    if sev_parts:
        parts.append(f"Severity breakdown: {', '.join(sev_parts)}.")

    return " ".join(parts)


def _generate_recommended_actions(
    findings: list[FindingInput],
    chains: list[EvidenceChainInput],
    score: RiskScore,
) -> list[str]:
    """Generate recommended actions based on risk profile."""
    actions: list[str] = []

    if score.overall >= 9.0:
        actions.append(
            "IMMEDIATE: Escalate to security team. Consider disabling affected targets."
        )
    elif score.overall >= 7.0:
        actions.append(
            "URGENT: Schedule remediation within 24 hours. Review affected targets."
        )

    # Attack-type specific recommendations
    attack_types = {f.attack_type for f in findings if f.attack_type}
    if "prompt_injection" in attack_types:
        actions.append("Implement input sanitization and prompt hardening.")
    if "data_exfiltration" in attack_types:
        actions.append("Review output filtering and data loss prevention controls.")
    if "jailbreak" in attack_types:
        actions.append("Strengthen system prompt boundaries and model guardrails.")

    if chains:
        actions.append(
            "Investigate attack chains for multi-step exploitation paths."
        )

    # General recommendations
    unique_targets = {f.target_id for f in findings}
    if len(unique_targets) > 1:
        actions.append(
            f"Audit all {len(unique_targets)} affected targets for shared vulnerabilities."
        )

    if not actions:
        actions.append("Monitor and reassess during next validation cycle.")

    return actions


# ─── Risk Correlation Engine ──────────────────────────────────────────────────


class RiskCorrelationEngine:
    """Produces correlated Risk Incidents from Findings, Evidence Chains,
    Validation Results, and Attack Chains.

    Stateless, composable, protocol-driven. The scoring algorithm can be
    replaced without modifying correlation logic.

    Usage:
        engine = RiskCorrelationEngine()
        incidents = engine.correlate(findings, chains, validations)
    """

    def __init__(
        self,
        calculator: RiskScoreCalculator | None = None,
        extractor: RiskFactorExtractor | None = None,
    ) -> None:
        self._calculator: RiskScoreCalculator = calculator or DefaultRiskScoreCalculator()
        self._extractor = extractor or RiskFactorExtractor()
        self._incident_counter = 0

    def correlate(
        self,
        findings: list[FindingInput],
        chains: list[EvidenceChainInput] | None = None,
        validations: list[ValidationResultInput] | None = None,
    ) -> list[RiskIncident]:
        """Produce Risk Incidents from correlated inputs.

        Groups findings by target, extracts risk factors, scores each group,
        and produces incidents with executive summaries and actions.
        """
        chains = chains or []
        validations = validations or []

        if not findings:
            return []

        # Group findings by target for incident creation
        target_groups = self._group_by_target(findings)
        incidents: list[RiskIncident] = []

        for target_id, target_findings in target_groups.items():
            # Filter chains and validations relevant to this target
            target_chains = [c for c in chains if c.target_id == target_id]
            target_validations = [v for v in validations if v.target_id == target_id]

            incident = self._create_incident(
                target_id=target_id,
                findings=target_findings,
                chains=target_chains,
                validations=target_validations,
            )
            incidents.append(incident)

        # Sort by score descending (highest risk first)
        incidents.sort(key=lambda i: i.risk_score.overall, reverse=True)
        return incidents

    def merge_incidents(
        self,
        incidents: list[RiskIncident],
    ) -> RiskIncident | None:
        """Merge related incidents into a single consolidated incident.

        Recalculates score from the combined factor set.
        Returns None if input is empty.
        """
        if not incidents:
            return None
        if len(incidents) == 1:
            return incidents[0]

        # Combine all data
        all_finding_ids: list[str] = []
        all_chain_ids: list[str] = []
        all_run_ids: list[str] = []
        all_targets: set[str] = set()
        all_attack_types: set[str] = set()
        all_factors: list[RiskFactor] = []

        for inc in incidents:
            all_finding_ids.extend(inc.finding_ids)
            all_chain_ids.extend(inc.evidence_chain_ids)
            all_run_ids.extend(inc.validation_run_ids)
            all_targets.update(inc.affected_targets)
            all_attack_types.update(inc.attack_types)
            all_factors.extend(inc.risk_score.factors)

        # Recalculate with merged factors (deduplicate by type, keep highest)
        best_factors: dict[RiskFactorType, RiskFactor] = {}
        for f in all_factors:
            existing = best_factors.get(f.factor_type)
            if existing is None or f.weighted_score > existing.weighted_score:
                best_factors[f.factor_type] = f

        merged_score = self._calculator.calculate(list(best_factors.values()))
        now = datetime.now(UTC)

        self._incident_counter += 1
        return RiskIncident(
            incident_id=f"RI-MERGED-{self._incident_counter}",
            organization_id=incidents[0].organization_id,
            risk_score=merged_score,
            priority=merged_score.priority,
            status=IncidentStatus.OPEN,
            title=f"Merged Incident: {len(all_targets)} targets, {len(all_finding_ids)} findings",
            executive_summary=(
                f"Merged from {len(incidents)} related incidents. "
                f"Score: {merged_score.overall:.1f}/10.0. "
                f"{len(all_targets)} target(s) affected."
            ),
            recommended_actions=incidents[0].recommended_actions,
            affected_targets=sorted(all_targets),
            finding_ids=all_finding_ids,
            evidence_chain_ids=all_chain_ids,
            validation_run_ids=all_run_ids,
            attack_types=sorted(all_attack_types),
            trend=RiskTrend.NEW,
            history=RiskHistory(),
            created_at=now,
            updated_at=now,
        )

    def _create_incident(
        self,
        target_id: str,
        findings: list[FindingInput],
        chains: list[EvidenceChainInput],
        validations: list[ValidationResultInput],
    ) -> RiskIncident:
        """Create a single risk incident for a target group."""
        # Extract factors
        factors = self._extractor.extract(findings, chains, validations)

        # Calculate score
        score = self._calculator.calculate(factors)

        # Generate outputs
        summary = _generate_executive_summary(findings, chains, score)
        actions = _generate_recommended_actions(findings, chains, score)

        # Collect metadata
        finding_ids = [f.finding_id for f in findings]
        chain_ids = [c.chain_id for c in chains]
        run_ids = list({v.run_id for v in validations} | {f.run_id for f in findings})
        attack_types = sorted({f.attack_type for f in findings if f.attack_type})
        org_id = findings[0].organization_id if findings else ""

        now = datetime.now(UTC)
        self._incident_counter += 1

        history = RiskHistory()
        history.add(score.overall, score.priority, "Incident created")

        return RiskIncident(
            incident_id=f"RI-{self._incident_counter:06d}",
            organization_id=org_id,
            risk_score=score,
            priority=score.priority,
            status=IncidentStatus.OPEN,
            title=self._generate_title(findings, attack_types),
            executive_summary=summary,
            recommended_actions=actions,
            affected_targets=[target_id],
            finding_ids=finding_ids,
            evidence_chain_ids=chain_ids,
            validation_run_ids=run_ids,
            attack_types=attack_types,
            trend=RiskTrend.NEW,
            history=history,
            created_at=now,
            updated_at=now,
        )

    def _group_by_target(
        self, findings: list[FindingInput]
    ) -> dict[str, list[FindingInput]]:
        """Group findings by target_id."""
        groups: dict[str, list[FindingInput]] = {}
        for f in findings:
            groups.setdefault(f.target_id, []).append(f)
        return groups

    def _generate_title(
        self, findings: list[FindingInput], attack_types: list[str]
    ) -> str:
        """Generate a descriptive incident title."""
        if not findings:
            return "Risk Incident"

        if attack_types:
            primary_attack = attack_types[0].replace("_", " ").title()
            if len(attack_types) > 1:
                return f"{primary_attack} and {len(attack_types) - 1} other attack type(s)"
            return f"{primary_attack} detected"

        max_sev = max(findings, key=lambda f: _severity_to_score(f.severity))
        return f"{max_sev.severity.title()} risk: {max_sev.title}"
