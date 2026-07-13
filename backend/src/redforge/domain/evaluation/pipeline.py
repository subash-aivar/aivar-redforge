"""EvaluationEngine — the top-level pipeline orchestrator.

Pipeline: Evidence Normalization -> Rule Evaluation -> Semantic
Evaluation -> Pattern Matching -> Risk Scoring -> Confidence
Calculation -> Finding Recommendation -> Knowledge Graph Projection.

EvaluationEngine depends only on Protocols — every stage is injected,
swappable, independently testable. It contains NO detection logic, NO
scoring logic, and NO remediation logic itself; it only sequences calls
to what it was given and applies one small, transparent, documented
piece of genuinely-new cross-stage logic: determining the overall
AttackOutcome from the collected evaluation trail (see
_determine_outcome). Same discipline as domain.planning.AttackPlanner
and domain.payloads.PayloadIntelligenceEngine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.evaluation.entity import EvaluationResult
from redforge.domain.evaluation.exceptions import NoEvaluatorsConfiguredError
from redforge.domain.evaluation.value_objects import AttackOutcome

if TYPE_CHECKING:
    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.evaluation.protocols import (
        ConfidenceCalculator,
        EvaluatorProtocol,
        EvidenceNormalizer,
        FindingBuilder,
        KnowledgeProjector,
        RemediationAdvisor,
        RiskScorer,
    )
    from redforge.domain.evaluation.value_objects import Confidence, EvaluationEvidence
    from redforge.domain.evidence.entity import Evidence
    from redforge.domain.findings.value_objects import Severity
    from redforge.shared.identifiers import EntityId

# Confidence threshold above which an evaluator's opinion counts toward
# the outcome vote — an evaluator that fired but is itself unsure
# (confidence < 0.5) contributes to the trail (for audit) but not to
# the majority-outcome decision.
_VOTE_CONFIDENCE_THRESHOLD = 0.5


class EvaluationEngine:
    """Default EvaluationEngineProtocol implementation.

    Every collaborator has no domain-owned default implementation —
    unlike domain.planning.AttackPlanner or
    domain.payloads.PayloadIntelligenceEngine, this engine's stages
    (Rule/Semantic/Pattern evaluation, Risk Scoring, Confidence
    Calculation, Finding Recommendation, Remediation Advice, Knowledge
    Projection) all wrap real, substantial, already-existing detection/
    scoring logic (application/runtime/evaluation/, application/risk_engine.py)
    — providing a "simple domain default" for any of them would mean
    reimplementing that existing logic, which this sprint was explicitly
    told not to do. See application/evaluation_adapters.py for the real,
    production implementations every collaborator here is deliberately
    required (not merely allowed) to be supplied.
    """

    def __init__(
        self,
        normalizer: EvidenceNormalizer,
        rule_evaluators: tuple[EvaluatorProtocol, ...],
        semantic_evaluators: tuple[EvaluatorProtocol, ...],
        pattern_evaluators: tuple[EvaluatorProtocol, ...],
        risk_scorer: RiskScorer,
        confidence_calculator: ConfidenceCalculator,
        finding_builder: FindingBuilder,
        remediation_advisor: RemediationAdvisor,
        *,
        knowledge_projector: KnowledgeProjector | None = None,
    ) -> None:
        if not (rule_evaluators or semantic_evaluators or pattern_evaluators):
            raise NoEvaluatorsConfiguredError()
        self._normalizer = normalizer
        self._rule_evaluators = rule_evaluators
        self._semantic_evaluators = semantic_evaluators
        self._pattern_evaluators = pattern_evaluators
        self._risk_scorer = risk_scorer
        self._confidence_calculator = confidence_calculator
        self._finding_builder = finding_builder
        self._remediation_advisor = remediation_advisor
        self._knowledge_projector = knowledge_projector

    async def evaluate(
        self,
        evidence: Evidence,
        attack: AttackDefinition,
        target_id: EntityId,
        organization_id: EntityId,
        *,
        attack_plan_id: EntityId | None = None,
    ) -> EvaluationResult:
        """Run the full 8-stage pipeline and produce an immutable
        EvaluationResult.

        Raises:
            EmptyEvaluationTrailError: If every configured evaluator
                produces zero results (should not happen if at least
                one evaluator is configured per __init__'s guard, but
                surfaced by EvaluationResult.create() as the final
                invariant check regardless).
        """
        # ── Stage 1: Evidence Normalization ─────────────────────────
        normalized = self._normalizer.normalize(evidence)

        # ── Stage 2-4: Rule / Semantic / Pattern Evaluation ─────────
        trail: list[EvaluationEvidence] = []
        for evaluator in (
            *self._rule_evaluators, *self._semantic_evaluators, *self._pattern_evaluators,
        ):
            trail.append(await evaluator.evaluate(normalized))
        trail_tuple = tuple(trail)

        outcome = self._determine_outcome(trail_tuple)

        # ── Stage 5: Risk Scoring ────────────────────────────────────
        risk_contribution = self._risk_scorer.score(outcome, trail_tuple, attack)

        # ── Stage 6: Confidence Calculation ─────────────────────────
        confidence = self._confidence_calculator.calculate(trail_tuple)

        # ── Stage 7: Finding Recommendation ─────────────────────────
        finding = self._finding_builder.build(outcome, trail_tuple, attack)
        remediation = (
            self._remediation_advisor.advise(outcome, attack, finding)
            if finding is not None else None
        )
        severity = self._severity_for(outcome, confidence) if finding is not None else None

        result = EvaluationResult.create(
            organization_id=organization_id,
            target_id=target_id,
            attack_id=attack.id,
            evidence_ids=(evidence.id,),
            outcome=outcome,
            confidence=confidence,
            evaluation_trail=trail_tuple,
            risk_contribution=risk_contribution,
            attack_plan_id=attack_plan_id,
            recommended_finding=finding,
            recommended_severity=severity,
            recommended_remediation=remediation,
        )

        # ── Stage 8: Knowledge Graph Projection ─────────────────────
        if self._knowledge_projector is not None:
            self._knowledge_projector.project(result)

        return result

    @staticmethod
    def _determine_outcome(trail: tuple[EvaluationEvidence, ...]) -> AttackOutcome:
        """Genuinely new, cross-stage decision logic — not a
        reimplementation of the existing engine's WeightedAverageAggregator
        (that decides which SINGLE outcome a set of evaluators converges
        on for a flat VULNERABLE/SECURE/ERROR/INCONCLUSIVE enum); this
        expresses the richer AttackOutcome including PARTIAL_SUCCESS,
        the value the existing flat enum structurally cannot represent.

        Rule, priority-ordered (not a switch statement — a sequence of
        independent checks over confident votes, each returning early):
        1. If every vote is ERROR -> ERROR.
        2. If every vote is INCONCLUSIVE (or no confident votes at all) -> INCONCLUSIVE.
        3. If all confident votes agree on SUCCESS -> SUCCESS.
        4. If all confident votes agree on FAILURE -> FAILURE.
        5. If confident votes are split between SUCCESS-leaning and
           FAILURE-leaning -> PARTIAL_SUCCESS (evaluators disagree on
           whether the attack succeeded — worth a human's attention,
           neither a clean pass nor a clean fail).
        """
        confident = [e for e in trail if e.confidence.score >= _VOTE_CONFIDENCE_THRESHOLD]

        if trail and all(e.outcome == AttackOutcome.ERROR for e in trail):
            return AttackOutcome.ERROR

        if not confident or all(e.outcome == AttackOutcome.INCONCLUSIVE for e in confident):
            return AttackOutcome.INCONCLUSIVE

        success_votes = sum(1 for e in confident if e.outcome == AttackOutcome.SUCCESS)
        failure_votes = sum(1 for e in confident if e.outcome == AttackOutcome.FAILURE)

        if success_votes and not failure_votes:
            return AttackOutcome.SUCCESS
        if failure_votes and not success_votes:
            return AttackOutcome.FAILURE
        if success_votes and failure_votes:
            return AttackOutcome.PARTIAL_SUCCESS
        return AttackOutcome.INCONCLUSIVE

    @staticmethod
    def _severity_for(outcome: AttackOutcome, confidence: Confidence) -> Severity:
        from redforge.domain.findings.value_objects import Severity

        score = confidence.score
        # A partial/disputed success is never over-stated to CRITICAL.
        ceiling = (
            Severity.MEDIUM if outcome == AttackOutcome.PARTIAL_SUCCESS
            else Severity.CRITICAL
        )

        if score >= 0.9:
            level = Severity.CRITICAL
        elif score >= 0.75:
            level = Severity.HIGH
        elif score >= 0.5:
            level = Severity.MEDIUM
        elif score >= 0.25:
            level = Severity.LOW
        else:
            level = Severity.INFORMATIONAL

        _rank = {
            Severity.INFORMATIONAL: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
            Severity.HIGH: 3, Severity.CRITICAL: 4,
        }
        return level if _rank[level] <= _rank[ceiling] else ceiling
