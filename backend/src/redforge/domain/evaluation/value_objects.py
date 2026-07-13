"""Value objects for the Response Evaluation Intelligence bounded context.

This is the canonical, immutable answer to "did this executed attack
actually succeed" — layered ON TOP OF the existing, already-complete
`application/runtime/evaluation/` engine (Evaluator/ConfidenceAggregator/
FindingCandidateGenerator/ExplainabilityProvider protocols;
KeywordEvaluator/PatternEvaluator/RuleEvaluator/SemanticEvaluator/
LLMJudgeEvaluator implementations — verified present and "Complete" per
docs/about-product.md before writing a line of this module), NOT a
replacement for it.

What was missing, and what this module adds: that existing engine
produces `EvaluationRunResult` — a rich but *application-layer*,
*non-persisted*, *identity-less* bundle of dataclasses, rebuilt fresh on
every pipeline run. There is no canonical, immutable, ID-bearing
aggregate an EvaluationResult can be looked up by, superseded, or
referenced from Findings/Risk/the Knowledge Graph the way
AttackDefinition/AttackPlan/PayloadBundle already are. `EvaluationResult`
(entity.py) is that missing aggregate. `application/evaluation_adapters.py`
bridges the two: it wraps the existing evaluator classes behind this
module's `EvaluatorProtocol`, and wraps `DefaultFindingGenerator`,
`HeuristicConfidenceCalculator`, and `StaticRemediationProvider` behind
this module's `FindingBuilder`/`ConfidenceCalculator`/`RemediationAdvisor`
— so the actual detection/scoring/remediation LOGIC still runs in the
one place it already existed; this module only gives its output
identity, immutability, and a place in the domain graph.

Naming collisions, resolved the same way Sprints 14/15 resolved
AttackPlan/ExecutionStrategy/PayloadGenerator/ProviderAdapter: this
module's `ConfidenceCalculator` is a *different* Protocol shape than
`application.runtime.evaluation.contracts.ConfidenceCalculator` (that
one assesses calibration risk on an already-aggregated verdict; this
one produces the canonical `Confidence` for the whole `EvaluationResult`
from a normalized evaluation trail — a higher-altitude, cross-stage
concern). Both are documented so neither is mistaken for the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique

from redforge.domain.evidence.value_objects import Confidence
from redforge.domain.findings.value_objects import Severity as RecommendedSeverity

__all__ = [
    "AttackOutcome",
    "Confidence",
    "EvaluationEvidence",
    "EvaluationStage",
    "EvaluationStatus",
    "NormalizedEvidence",
    "RecommendedFinding",
    "RecommendedRemediation",
    "RecommendedSeverity",
    "RiskContribution",
]


@unique
class AttackOutcome(StrEnum):
    """The canonical, red-team-perspective verdict: did the attack
    succeed against the target?

    Distinct from (and richer than) the existing engine's
    `EvaluationOutcome` (VULNERABLE/SECURE/ERROR/INCONCLUSIVE) — mapped
    from it 1:1 for SUCCESS/FAILURE/ERROR/INCONCLUSIVE by
    application/evaluation_adapters.py, plus PARTIAL_SUCCESS, a genuinely
    new value this engine's own outcome-determination logic can express
    when evaluators disagree (some indicate success, some don't) rather
    than forcing a false binary the existing flat enum cannot represent.
    """

    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@unique
class EvaluationStage(StrEnum):
    """Which canonical pipeline stage produced a given EvaluationEvidence
    entry — the audit tag Stage 1 (Normalization) attaches to every
    entry, and every later stage inherits."""

    RULE = "rule"
    SEMANTIC = "semantic"
    PATTERN = "pattern"


@unique
class EvaluationStatus(StrEnum):
    """Lifecycle status of an EvaluationResult — the same two-state
    immutable-except-supersede pattern as domain.planning.PlanStatus
    and domain.payloads.BundleStatus."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class NormalizedEvidence:
    """Stage 1 (Evidence Normalization) output — a uniform shape every
    Rule/Semantic/Pattern evaluator consumes, regardless of whether the
    underlying signal came from `domain.evidence.Evidence`,
    `application.runtime.orchestrator.ExecutionResult`, or a
    `Conversation`. Building this once, centrally, is what lets the same
    evaluator run against any of those sources without each evaluator
    needing to know which one it got.
    """

    request_text: str
    response_text: str
    attack_category: str
    target_id: str
    response_status: int = 0
    duration_ms: int = 0
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvaluationEvidence:
    """One evaluator's normalized opinion — the canonical shape every
    Rule/Semantic/Pattern evaluator's output is translated into
    (`application.evaluation_adapters` translates the existing engine's
    `EvaluatorResult` into this shape 1:1; nothing about the detection
    logic itself is reimplemented here).
    """

    stage: EvaluationStage
    evaluator_name: str
    outcome: AttackOutcome
    confidence: Confidence
    rationale: str = ""
    indicators: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evaluator_name:
            raise ValueError("evaluator_name must not be empty")


@dataclass(frozen=True, slots=True)
class RiskContribution:
    """Stage 5 (Risk Scoring) output — how much this one evaluation
    should weigh into the platform's overall risk picture.

    Deliberately shaped to convert cleanly into
    `application.risk_engine.RiskFactor` (impact/likelihood ->
    factor scores, exploitability -> its own factor) without this
    domain module importing that application-layer type — the
    conversion is application.evaluation_adapters' job, not this VO's.
    """

    impact: float  # 0.0 (none) .. 10.0 (catastrophic) — CVSS-like scale
    likelihood: float  # 0.0 (unlikely) .. 1.0 (certain)
    exploitability: float  # 0.0 (hard to exploit) .. 1.0 (trivial)
    rationale: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.impact <= 10.0:
            raise ValueError("impact must be between 0.0 and 10.0")
        if not 0.0 <= self.likelihood <= 1.0:
            raise ValueError("likelihood must be between 0.0 and 1.0")
        if not 0.0 <= self.exploitability <= 1.0:
            raise ValueError("exploitability must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class RecommendedFinding:
    """Stage 7 (Finding Recommendation) output — what a
    `domain.findings.Finding` would say if one were created from this
    evaluation. NOT a persisted Finding itself: creating the real
    aggregate (via `Finding.create_from_evidence(...)`, which already
    exists and already accepts evidence_ids + recommendation) is an
    application-layer decision this domain module does not make —
    mirrors the existing engine's own `FindingCandidate` design
    intent ("This is NOT a domain Finding entity... passed to the
    existing Findings domain for persistence").
    """

    title: str
    description: str
    evidence_summary: str = ""

    def __post_init__(self) -> None:
        if not self.title:
            raise ValueError("title must not be empty")
        if not self.description:
            raise ValueError("description must not be empty")


@dataclass(frozen=True, slots=True)
class RecommendedRemediation:
    """Stage 7 output — the recommended fix, distinct from
    RecommendedFinding (what's wrong) — this is what to do about it."""

    summary: str
    priority: str = "medium"  # "immediate" | "high" | "medium" | "low"
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.summary:
            raise ValueError("summary must not be empty")
        if self.priority not in {"immediate", "high", "medium", "low"}:
            raise ValueError(
                f"priority must be 'immediate', 'high', 'medium', or 'low', "
                f"got '{self.priority}'"
            )
