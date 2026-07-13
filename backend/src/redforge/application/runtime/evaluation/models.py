"""Evaluation domain models — immutable value objects.

These are application-layer models (not domain entities).
They carry evaluation results through the pipeline without
duplicating existing Evidence or Finding domain concepts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, unique
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redforge.application.runtime.contracts import ClassificationResult
    from redforge.application.runtime.evaluation.consensus import ConsensusResult
    from redforge.application.runtime.evaluation.policy import PolicyResult


@unique
class EvaluationOutcome(StrEnum):
    """Result of a single evaluator's assessment."""

    VULNERABLE = "vulnerable"  # Attack succeeded — security issue found
    SECURE = "secure"  # Target correctly resisted the attack
    ERROR = "error"  # Evaluator could not determine (execution error)
    INCONCLUSIVE = "inconclusive"  # Insufficient signal to decide


@dataclass(frozen=True, slots=True)
class EvaluatorResult:
    """Output of one evaluator analyzing one piece of evidence.

    Each evaluator produces one of these independently.
    The aggregator combines them into a final verdict.
    """

    evaluator_name: str
    outcome: EvaluationOutcome
    confidence: float  # 0.0 to 1.0
    reasoning: str = ""
    indicators: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """Context provided to evaluators for one evidence assessment.

    Contains everything an evaluator needs without accessing
    infrastructure directly. Read-only.
    """

    step_id: str
    attack_id: str
    attack_name: str
    attack_category: str
    target_id: str
    request_body: str
    response_body: str
    response_status: int
    duration_ms: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AggregatedEvaluation:
    """Final evaluation after all evaluators have run and been aggregated.

    This is the output of the evaluation pipeline — ready for
    finding generation and integration with the runtime.
    """

    step_id: str
    attack_id: str
    outcome: EvaluationOutcome
    confidence: float
    evaluator_results: tuple[EvaluatorResult, ...]
    reasoning: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_vulnerable(self) -> bool:
        return self.outcome == EvaluationOutcome.VULNERABLE

    @property
    def evaluator_count(self) -> int:
        return len(self.evaluator_results)

    @property
    def agreement_ratio(self) -> float:
        """Fraction of evaluators that agree with the final outcome."""
        if not self.evaluator_results:
            return 0.0
        agreeing = sum(
            1 for r in self.evaluator_results
            if r.outcome == self.outcome
        )
        return agreeing / len(self.evaluator_results)


@dataclass(frozen=True, slots=True)
class FindingCandidate:
    """A potential finding generated from evaluation results.

    This is NOT a domain Finding entity. It is a candidate
    that the Findings domain can accept or reject.
    """

    attack_id: str
    attack_name: str
    attack_category: str
    target_id: str
    step_id: str
    title: str
    description: str
    severity: str
    confidence: float
    evidence_summary: str
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OwaspControlMatch:
    """A matched OWASP Top 10 for LLM Applications control.

    Distinct from domain.findings.value_objects.OwaspReference: this is
    the evaluation-layer *candidate* match (with a match confidence);
    ValidationService converts accepted matches into OwaspReference when
    attaching them to a persisted Finding.
    """

    category_id: str
    category_name: str
    match_confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.category_id:
            raise ValueError("category_id must not be empty")
        if self.match_confidence < 0.0 or self.match_confidence > 1.0:
            raise ValueError("match_confidence must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class MitreTechniqueMatch:
    """A matched MITRE ATLAS technique. See taxonomy.py module docstring
    for the accuracy caveat on technique IDs."""

    technique_id: str
    technique_name: str
    tactic: str = ""
    match_confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.technique_id:
            raise ValueError("technique_id must not be empty")
        if self.match_confidence < 0.0 or self.match_confidence > 1.0:
            raise ValueError("match_confidence must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Calibration self-assessment for one evaluation decision.

    Distinct from `confidence` (how strongly the evaluators believe the
    verdict) — this is "how likely is this verdict to be *wrong*, and in
    which direction." A high-confidence VULNERABLE verdict can still carry
    real false-positive risk (e.g., a single aggressive keyword match);
    this field lets a human reviewer or downstream automation triage
    findings by miscalibration risk, not just raw confidence.
    """

    false_positive_risk: float  # 0.0 (no FP risk) .. 1.0 (likely FP)
    false_negative_risk: float  # 0.0 (no FN risk) .. 1.0 (likely FN)
    rationale: str = ""

    def __post_init__(self) -> None:
        if not (0.0 <= self.false_positive_risk <= 1.0):
            raise ValueError("false_positive_risk must be between 0.0 and 1.0")
        if not (0.0 <= self.false_negative_risk <= 1.0):
            raise ValueError("false_negative_risk must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class ExplainabilityTrace:
    """Full audit trail behind one evaluation decision.

    Every field here answers a specific audit question an enterprise
    security reviewer will ask when triaging a finding:
      - contributing_evaluators / evaluator_reasonings → "which evaluators
        fired, and what did each one individually conclude?"
      - confidence_method / confidence_rationale → "how was the final
        confidence number actually derived?"
      - remediation_rationale → "why was this specific remediation
        recommended, not a different one?"
    """

    contributing_evaluators: tuple[str, ...]
    evaluator_reasonings: tuple[tuple[str, str], ...]  # (evaluator_name, reasoning)
    confidence_method: str
    confidence_rationale: str
    remediation_rationale: str

    def format_summary(self) -> str:
        """Human-readable audit summary (for reports/UI, not machine parsing)."""
        lines = [
            f"Confidence method: {self.confidence_method}",
            f"Confidence rationale: {self.confidence_rationale}",
        ]
        for name, reasoning in self.evaluator_reasonings:
            lines.append(f"  - {name}: {reasoning}")
        if self.remediation_rationale:
            lines.append(f"Remediation rationale: {self.remediation_rationale}")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class EvaluationIntelligence:
    """Enterprise-grade explainable evaluation output.

    This is what separates a rule-based validator from a security
    reasoning platform: instead of a bare VULNERABLE/SECURE verdict, every
    evaluation carries the "why" — matched frameworks, supporting
    evidence, calibration risk, and a full decision audit trail.

    Produced by an ExplainabilityProvider from an AggregatedEvaluation.
    Optional on EvaluationRunResult — evaluators/pipelines that don't
    configure an ExplainabilityProvider simply don't populate it, and
    every existing consumer of AggregatedEvaluation/ClassificationResult
    keeps working unchanged (see EvaluationRunResult docstring).
    """

    matched_security_objectives: tuple[str, ...]
    matched_threat_coverage: tuple[str, ...]
    matched_owasp_controls: tuple[OwaspControlMatch, ...]
    matched_mitre_techniques: tuple[MitreTechniqueMatch, ...]
    supporting_evidence: tuple[str, ...]
    reasoning_summary: str
    recommended_remediation: str
    risk_assessment: RiskAssessment
    explainability: ExplainabilityTrace


@dataclass(frozen=True, slots=True)
class EvaluationRunResult:
    """Complete, self-contained output of one EvaluationPipeline.evaluate() call.

    Bundles the runtime-compatible ClassificationResult with the richer
    AggregatedEvaluation, an optional FindingCandidate, and an optional
    EvaluationIntelligence (populated only when the pipeline was
    configured with an ExplainabilityProvider). Callers that need only
    pass/fail use `classification`; callers building an audit trail or
    an explainable Finding use `intelligence`.

    This type exists so EvaluationPipeline never has to stash results on
    `self` between calls — every caller gets its own result object, so
    concurrent evaluate() calls on a shared pipeline instance cannot
    observe each other's data.
    """

    classification: ClassificationResult
    aggregated: AggregatedEvaluation
    finding_candidate: FindingCandidate | None = None
    intelligence: EvaluationIntelligence | None = None
    # Populated when EvaluationPipeline is configured with ConsensusEngine
    consensus_result: ConsensusResult | None = None
    # Populated when EvaluationPipeline is configured with EvaluationPolicyEnforcer
    policy_result: PolicyResult | None = None
