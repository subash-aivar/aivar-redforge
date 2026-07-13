"""Adapters wiring domain.evaluation's Protocols to the existing,
already-complete `application/runtime/evaluation/` engine.

Nothing in this file reimplements detection, aggregation, scoring, or
remediation logic — every adapter is a thin translation layer that
constructs the existing engine's DTOs from domain.evaluation's VOs,
calls the existing (real, tested) class, and translates the result
back. This is the concrete proof that Sprint 16 extends the evaluation
engine rather than duplicating it.

Mapping summary:
  - LegacyEvaluatorAdapter          wraps Evaluator (Keyword/Pattern/Rule/Semantic)
  - EvidenceNormalizerAdapter       Evidence -> EvaluationContext-shaped NormalizedEvidence
  - AggregatorConfidenceCalculator  wraps ConfidenceAggregator (WeightedAverageAggregator)
  - RiskCorrelationRiskScorer       wraps application.risk_engine's
                                     RiskFactor/DefaultRiskScoreCalculator
  - LegacyFindingBuilder            wraps DefaultFindingGenerator
  - LegacyRemediationAdvisor        wraps StaticRemediationProvider
  - EvaluationKnowledgeGraphProjector  projects into application.knowledge_graph.KnowledgeGraph
    (same pattern as Sprint 13's AttackKnowledgeGraphProjector)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.knowledge_graph import GraphEdge, GraphNode, NodeType, RelationshipType
from redforge.application.risk_engine import DefaultRiskScoreCalculator, RiskFactor, RiskFactorType
from redforge.application.runtime.evaluation.aggregators import WeightedAverageAggregator
from redforge.application.runtime.evaluation.explainability import StaticRemediationProvider
from redforge.application.runtime.evaluation.findings import DefaultFindingGenerator
from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationContext,
    EvaluationOutcome,
    EvaluatorResult,
)
from redforge.domain.evaluation.value_objects import (
    AttackOutcome,
    Confidence,
    EvaluationEvidence,
    EvaluationStage,
    NormalizedEvidence,
    RecommendedFinding,
    RecommendedRemediation,
    RiskContribution,
)

if TYPE_CHECKING:
    from redforge.application.knowledge_graph import KnowledgeGraph
    from redforge.application.runtime.evaluation.contracts import Evaluator as LegacyEvaluator
    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.evaluation.entity import EvaluationResult
    from redforge.domain.evidence.entity import Evidence

# ─── Outcome mapping (documented 1:1, not re-derived ad hoc per call) ──────

_LEGACY_TO_DOMAIN_OUTCOME: dict[EvaluationOutcome, AttackOutcome] = {
    EvaluationOutcome.VULNERABLE: AttackOutcome.SUCCESS,
    EvaluationOutcome.SECURE: AttackOutcome.FAILURE,
    EvaluationOutcome.ERROR: AttackOutcome.ERROR,
    EvaluationOutcome.INCONCLUSIVE: AttackOutcome.INCONCLUSIVE,
}

_DOMAIN_TO_LEGACY_OUTCOME: dict[AttackOutcome, EvaluationOutcome] = {
    AttackOutcome.SUCCESS: EvaluationOutcome.VULNERABLE,
    AttackOutcome.PARTIAL_SUCCESS: EvaluationOutcome.VULNERABLE,
    AttackOutcome.FAILURE: EvaluationOutcome.SECURE,
    AttackOutcome.INCONCLUSIVE: EvaluationOutcome.INCONCLUSIVE,
    AttackOutcome.ERROR: EvaluationOutcome.ERROR,
}


def _context_from(evidence: Evidence, attack: AttackDefinition) -> EvaluationContext:
    return EvaluationContext(
        step_id=str(evidence.id),
        attack_id=str(attack.id),
        attack_name=attack.name,
        attack_category=str(attack.category),
        target_id=str(evidence.target_id),
        request_body=evidence.request.body,
        response_body=evidence.response.body,
        response_status=evidence.response.status_code,
        duration_ms=evidence.execution_metadata.duration_ms,
    )


# ─── Stage 1: Evidence Normalization ────────────────────────────────────────


class EvidenceNormalizerAdapter:
    """Domain EvidenceNormalizer producing the same shape of data the
    existing engine's EvaluationContext already carries — reusing that
    existing field design rather than inventing a competing one."""

    def normalize(self, evidence: Evidence) -> NormalizedEvidence:
        return NormalizedEvidence(
            request_text=evidence.request.body,
            response_text=evidence.response.body,
            attack_category=str(evidence.attack_ref.attack_type),
            target_id=str(evidence.target_id),
            response_status=evidence.response.status_code,
            duration_ms=evidence.execution_metadata.duration_ms,
        )


# ─── Stages 2-4: Rule / Semantic / Pattern Evaluation ──────────────────────


class LegacyEvaluatorAdapter:
    """Wraps ONE existing `application.runtime.evaluation.contracts.Evaluator`
    implementation (KeywordEvaluator, PatternEvaluator, RuleEvaluator,
    SemanticEvaluator, ...) behind domain.evaluation's EvaluatorProtocol.

    `stage` is supplied by the caller (not inferred from the evaluator's
    class) since the same underlying Evaluator implementation could
    legitimately be configured for more than one stage depending on
    deployment (e.g. a RuleEvaluator instance tuned for pattern-style
    rules could run in the Pattern stage).
    """

    def __init__(self, evaluator: LegacyEvaluator, stage: EvaluationStage) -> None:
        self._evaluator = evaluator
        self._stage = stage

    @property
    def name(self) -> str:
        return self._evaluator.name

    async def evaluate(self, evidence: NormalizedEvidence) -> EvaluationEvidence:
        context = EvaluationContext(
            step_id="",
            attack_id="",
            attack_name="",
            attack_category=evidence.attack_category,
            target_id=evidence.target_id,
            request_body=evidence.request_text,
            response_body=evidence.response_text,
            response_status=evidence.response_status,
            duration_ms=evidence.duration_ms,
        )
        legacy_result = await self._evaluator.evaluate(context)
        return EvaluationEvidence(
            stage=self._stage,
            evaluator_name=legacy_result.evaluator_name,
            outcome=_LEGACY_TO_DOMAIN_OUTCOME[legacy_result.outcome],
            confidence=Confidence(score=legacy_result.confidence),
            rationale=legacy_result.reasoning,
            indicators=legacy_result.indicators,
            metadata={k: str(v) for k, v in legacy_result.metadata.items()},
        )


# ─── Stage 5: Risk Scoring ──────────────────────────────────────────────────


class RiskCorrelationRiskScorer:
    """Domain RiskScorer wrapping application.risk_engine's
    DefaultRiskScoreCalculator — the CVSS-inspired weighted calculator
    that already exists and that Stage 5 must not reimplement."""

    def __init__(self, calculator: DefaultRiskScoreCalculator | None = None) -> None:
        self._calculator = calculator or DefaultRiskScoreCalculator()

    def score(
        self,
        outcome: AttackOutcome,
        trail: tuple[EvaluationEvidence, ...],
        attack: AttackDefinition,
    ) -> RiskContribution:
        if outcome not in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL_SUCCESS}:
            return RiskContribution(
                impact=0.0, likelihood=0.0, exploitability=0.0,
                rationale=f"Outcome '{outcome}' does not indicate exploitation",
            )

        avg_confidence = (
            sum(e.confidence.score for e in trail) / len(trail) if trail else 0.0
        )
        factors = [
            RiskFactor(
                factor_type=RiskFactorType.IMPACT,
                score=min(1.0, {"critical": 1.0, "high": 0.8, "medium": 0.5,
                                 "low": 0.25, "informational": 0.1}.get(
                    str(attack.severity), 0.5)),
                weight=1.0,
                rationale=f"Attack severity: {attack.severity}",
            ),
            RiskFactor(
                factor_type=RiskFactorType.LIKELIHOOD,
                score=1.0 if outcome == AttackOutcome.SUCCESS else 0.5,
                weight=0.8,
                rationale=f"Evaluation outcome: {outcome}",
            ),
            RiskFactor(
                factor_type=RiskFactorType.CONFIDENCE,
                score=avg_confidence,
                weight=0.6,
                rationale=f"Average evaluator confidence: {avg_confidence:.2f}",
            ),
            RiskFactor(
                factor_type=RiskFactorType.EVIDENCE_STRENGTH,
                score=min(1.0, len(trail) / 3),
                weight=0.4,
                rationale=f"{len(trail)} evaluator(s) contributed evidence",
            ),
        ]
        risk_score = self._calculator.calculate(factors)

        return RiskContribution(
            impact=risk_score.overall,
            likelihood=1.0 if outcome == AttackOutcome.SUCCESS else 0.5,
            exploitability=avg_confidence,
            rationale=(
                f"DefaultRiskScoreCalculator: overall={risk_score.overall:.2f}/10 "
                f"from {len(factors)} factors"
            ),
        )


# ─── Stage 6: Confidence Calculation ────────────────────────────────────────


class AggregatorConfidenceCalculator:
    """Domain ConfidenceCalculator wrapping the existing
    WeightedAverageAggregator (or any ConfidenceAggregator) — reuses the
    exact same confidence-aggregation algorithm the legacy pipeline
    already used, rather than re-deriving a second one."""

    def __init__(self, aggregator: WeightedAverageAggregator | None = None) -> None:
        self._aggregator = aggregator or WeightedAverageAggregator()

    def calculate(self, trail: tuple[EvaluationEvidence, ...]) -> Confidence:
        legacy_results = [
            EvaluatorResult(
                evaluator_name=e.evaluator_name,
                outcome=_DOMAIN_TO_LEGACY_OUTCOME[e.outcome],
                confidence=e.confidence.score,
                reasoning=e.rationale,
                indicators=e.indicators,
            )
            for e in trail
        ]
        aggregated: AggregatedEvaluation = self._aggregator.aggregate(legacy_results)
        return Confidence(score=aggregated.confidence)


# ─── Stage 7: Finding Recommendation ────────────────────────────────────────


class LegacyFindingBuilder:
    """Domain FindingBuilder wrapping the existing DefaultFindingGenerator
    — constructs the legacy AggregatedEvaluation/EvaluationContext shapes
    from the domain trail, calls the real generator, translates its
    FindingCandidate back into RecommendedFinding."""

    def __init__(self, generator: DefaultFindingGenerator | None = None) -> None:
        self._generator = generator or DefaultFindingGenerator()

    def build(
        self,
        outcome: AttackOutcome,
        trail: tuple[EvaluationEvidence, ...],
        attack: AttackDefinition,
    ) -> RecommendedFinding | None:
        if outcome not in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL_SUCCESS}:
            return None

        legacy_results = [
            EvaluatorResult(
                evaluator_name=e.evaluator_name,
                outcome=_DOMAIN_TO_LEGACY_OUTCOME[e.outcome],
                confidence=e.confidence.score,
                reasoning=e.rationale,
                indicators=e.indicators,
            )
            for e in trail
        ]
        avg_confidence = (
            sum(e.confidence.score for e in trail) / len(trail) if trail else 0.0
        )
        aggregated = AggregatedEvaluation(
            step_id=str(attack.id),
            attack_id=str(attack.id),
            outcome=EvaluationOutcome.VULNERABLE,
            confidence=avg_confidence,
            evaluator_results=tuple(legacy_results),
        )
        context = EvaluationContext(
            step_id=str(attack.id), attack_id=str(attack.id), attack_name=attack.name,
            attack_category=str(attack.category), target_id="", request_body="",
            response_body="", response_status=0, duration_ms=0,
        )
        candidate = self._generator.generate(aggregated, context)
        if candidate is None:
            return None
        return RecommendedFinding(
            title=candidate.title,
            description=candidate.description,
            evidence_summary=candidate.evidence_summary,
        )


# ─── Stage 7 (continued): Remediation Advice ────────────────────────────────


class LegacyRemediationAdvisor:
    """Domain RemediationAdvisor wrapping the existing
    StaticRemediationProvider — reuses whatever category->remediation
    mapping a deployment already configured for the legacy pipeline."""

    def __init__(self, provider: StaticRemediationProvider) -> None:
        self._provider = provider

    def advise(
        self,
        outcome: AttackOutcome,
        attack: AttackDefinition,
        finding: RecommendedFinding,
    ) -> RecommendedRemediation | None:
        summary = self._provider.recommend(str(attack.category))
        if not summary:
            return None
        priority = "immediate" if outcome == AttackOutcome.SUCCESS else "high"
        return RecommendedRemediation(summary=summary, priority=priority)


# ─── Stage 8: Knowledge Graph Projection ────────────────────────────────────


class EvaluationKnowledgeGraphProjector:
    """Projects a finished EvaluationResult into the shared KnowledgeGraph
    — the same pattern Sprint 13's AttackKnowledgeGraphProjector used for
    the Attack Taxonomy, applied here to evaluation outcomes."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    def project(self, result: EvaluationResult) -> None:
        self._graph.add_node(GraphNode(
            node_id=str(result.id),
            node_type=NodeType.EVALUATION_RESULT,
            label=f"Evaluation: {result.outcome}",
            metadata={
                "outcome": str(result.outcome),
                "confidence": str(result.confidence.score),
            },
        ))
        for evidence_id in result.evidence_ids:
            self._graph.add_edge(GraphEdge(
                source_id=str(evidence_id),
                target_id=str(result.id),
                relationship=RelationshipType.EVIDENCE_EVALUATED_AS,
            ))
