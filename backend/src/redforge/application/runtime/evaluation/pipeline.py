"""Evaluation Pipeline — multi-evaluator orchestration.

Runs multiple evaluators against evidence, aggregates their results,
and optionally generates finding candidates.

The pipeline implements the existing ResponseClassifier protocol,
making it a drop-in replacement for the simple KeywordClassifier.

Sprint 38/39 additions (backward compatible — all new params are optional):
- consensus_engine: if provided, ConsensusEngine.compute() runs after
  aggregation and ConsensusResult is attached to EvaluationRunResult.
- policy_enforcer + policy: if provided, EvaluationPolicyEnforcer.check()
  runs AFTER finding generation so the candidate's proposed_severity can be
  passed in. When policy says BLOCK_CRITICAL, the candidate's severity is
  capped (override_severity applied). PolicyResult is attached to EvaluationRunResult.

This is the ONLY place ConsensusEngine and EvaluationPolicyEnforcer run in
production; there is no parallel evaluation path.
"""

from __future__ import annotations

from redforge.application.runtime.contracts import ClassificationResult, StepEvidence
from redforge.application.runtime.evaluation.consensus import ConsensusEngine
from redforge.application.runtime.evaluation.contracts import (
    ConfidenceAggregator,
    Evaluator,
    ExplainabilityProvider,
    FindingCandidateGenerator,
)
from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationContext,
    EvaluationOutcome,
    EvaluationRunResult,
    EvaluatorResult,
    FindingCandidate,
)
from redforge.application.runtime.evaluation.policy import (
    EvaluationPolicy,
    EvaluationPolicyEnforcer,
    PolicyResult,
)
from redforge.core.logging import get_logger

logger = get_logger(__name__)


class EvaluationPipeline:
    """Multi-evaluator pipeline that implements ResponseClassifier.

    Runs evaluators in configured order, aggregates results,
    and produces a ClassificationResult compatible with the runtime.

    Stateless and concurrency-safe: every call to evaluate()/classify()
    computes and returns its own result. Nothing is stored on `self`
    between calls, so a single pipeline instance can be shared safely
    across concurrently executing validation runs.

    Usage (basic):
        pipeline = EvaluationPipeline(
            evaluators=[KeywordEvaluator(), PatternEvaluator()],
            aggregator=WeightedAverageAggregator(),
        )

    Usage (with consensus + policy gate):
        pipeline = EvaluationPipeline(
            evaluators=[KeywordEvaluator(), SecurityJudgeEvaluator(provider)],
            aggregator=WeightedAverageAggregator(),
            finding_generator=DefaultFindingGenerator(),
            consensus_engine=ConsensusEngine(quorum_threshold=0.67),
            policy_enforcer=EvaluationPolicyEnforcer(),
            policy=STRICT_POLICY,
        )

    All new parameters are optional. Pipelines built without them behave
    exactly as before — this is how Sprint 38/39 extends the pipeline
    without breaking existing callers.
    """

    def __init__(
        self,
        evaluators: list[Evaluator],
        aggregator: ConfidenceAggregator,
        finding_generator: FindingCandidateGenerator | None = None,
        explainability_provider: ExplainabilityProvider | None = None,
        consensus_engine: ConsensusEngine | None = None,
        policy_enforcer: EvaluationPolicyEnforcer | None = None,
        policy: EvaluationPolicy | None = None,
    ) -> None:
        self._evaluators = evaluators
        self._aggregator = aggregator
        self._finding_generator = finding_generator
        self._explainability_provider = explainability_provider
        self._consensus_engine = consensus_engine
        self._policy_enforcer = policy_enforcer
        self._policy = policy

    async def evaluate(
        self, evidence: StepEvidence, attack_name: str
    ) -> EvaluationRunResult:
        """Run all evaluators, aggregate, and return the full result.

        Pure: reads only its arguments and `self`'s injected collaborators.
        Writes no instance state. Safe to await concurrently from multiple
        in-flight validation runs sharing the same pipeline instance.

        Step sequence:
        1. Run all evaluators (per-evaluator error isolation)
        2. Aggregate results into AggregatedEvaluation
        3. Compute ConsensusResult (if consensus_engine configured)
        4. Generate FindingCandidate (severity needed for critical safety gate)
        5. Check EvaluationPolicy with proposed_severity from candidate
        6. Apply policy severity override to candidate (finding safety gate)
        7. Run ExplainabilityProvider (additive, non-fatal)
        8. Return EvaluationRunResult with all above attached
        """
        context = self._build_context(evidence, attack_name)

        # 1. Run all evaluators
        results: list[EvaluatorResult] = []
        for evaluator in self._evaluators:
            # Resolve evaluator identity safely — never let error reporting
            # raise a secondary exception that masks the original failure.
            evaluator_name = getattr(evaluator, "name", type(evaluator).__name__)
            try:
                result = await evaluator.evaluate(context)
                results.append(result)
            except Exception as exc:
                logger.warning(
                    "evaluator_error",
                    evaluator=evaluator_name,
                    error=str(exc),
                )
                results.append(EvaluatorResult(
                    evaluator_name=evaluator_name,
                    outcome=EvaluationOutcome.ERROR,
                    confidence=0.0,
                    reasoning=f"Evaluator error: {exc}",
                ))

        # 2. Aggregate
        aggregate = self._aggregator.aggregate(results)
        aggregated = AggregatedEvaluation(
            step_id=evidence.step_id,
            attack_id=evidence.attack_id,
            outcome=aggregate.outcome,
            confidence=aggregate.confidence,
            evaluator_results=aggregate.evaluator_results,
            reasoning=aggregate.reasoning,
        )

        # 3. Compute consensus (optional)
        consensus_result = None
        if self._consensus_engine is not None:
            consensus_result = self._consensus_engine.compute(list(results))

        # 4. Generate finding candidate before policy (severity required for critical gate)
        finding_candidate = None
        if self._finding_generator is not None and aggregated.is_vulnerable:
            finding_candidate = self._finding_generator.generate(aggregated, context)

        # 5. Check evaluation policy (optional) — pass proposed_severity from candidate
        policy_result = None
        if (
            self._policy_enforcer is not None
            and self._policy is not None
            and consensus_result is not None
        ):
            proposed_severity = (
                finding_candidate.severity if finding_candidate is not None else None
            )
            policy_result = self._policy_enforcer.check(
                self._policy, aggregated, consensus_result, context,
                proposed_severity=proposed_severity,
            )

        # 6. Apply policy severity override to candidate (finding safety gate)
        if finding_candidate is not None and policy_result is not None:
            finding_candidate = _apply_policy_severity(finding_candidate, policy_result)

        # 6. Explainability (additive, non-fatal)
        intelligence = None
        if self._explainability_provider is not None:
            try:
                intelligence = self._explainability_provider.explain(aggregated, context)
            except Exception as exc:
                logger.warning(
                    "explainability_provider_error",
                    step_id=evidence.step_id,
                    error=str(exc),
                )

        return EvaluationRunResult(
            classification=self._to_classification(aggregated),
            aggregated=aggregated,
            finding_candidate=finding_candidate,
            intelligence=intelligence,
            consensus_result=consensus_result,
            policy_result=policy_result,
        )

    async def classify(
        self, evidence: StepEvidence, attack_name: str
    ) -> ClassificationResult:
        """Implements ResponseClassifier protocol.

        Thin wrapper over evaluate() that returns only the
        runtime-compatible ClassificationResult.
        """
        outcome = await self.evaluate(evidence, attack_name)
        return outcome.classification

    @staticmethod
    def _build_context(
        evidence: StepEvidence, attack_name: str
    ) -> EvaluationContext:
        """Convert StepEvidence into EvaluationContext."""
        return EvaluationContext(
            step_id=evidence.step_id,
            attack_id=evidence.attack_id,
            attack_name=attack_name,
            attack_category=evidence.metadata.get("category", "unknown"),
            target_id=evidence.target_id,
            request_body=evidence.request_body,
            response_body=evidence.response_body,
            response_status=evidence.response_status,
            duration_ms=evidence.duration_ms,
            metadata=evidence.metadata,
        )

    @staticmethod
    def _to_classification(
        evaluation: AggregatedEvaluation,
    ) -> ClassificationResult:
        """Map EvaluationOutcome to runtime ClassificationResult."""
        outcome_map = {
            EvaluationOutcome.VULNERABLE: "fail",
            EvaluationOutcome.SECURE: "pass",
            EvaluationOutcome.ERROR: "error",
            EvaluationOutcome.INCONCLUSIVE: "inconclusive",
        }
        return ClassificationResult(
            outcome=outcome_map[evaluation.outcome],
            confidence=evaluation.confidence,
            reasoning=evaluation.reasoning,
        )


def _apply_policy_severity(
    candidate: FindingCandidate,
    policy_result: PolicyResult,
) -> FindingCandidate:
    """Apply policy override_severity to a finding candidate.

    When EvaluationPolicyEnforcer says BLOCK_CRITICAL, the proposed
    severity is capped at override_severity (typically "high").
    This is the canonical finding safety gate.
    """
    from redforge.application.runtime.evaluation.policy import PolicyAction

    if (
        policy_result.required_action == PolicyAction.BLOCK_CRITICAL
        and policy_result.override_severity is not None
        and candidate.severity == "critical"
    ):
        from dataclasses import replace
        logger.info(
            "policy_severity_override",
            step_id=candidate.step_id,
            original_severity="critical",
            override_severity=policy_result.override_severity,
            violations=[v.constraint for v in policy_result.violations],
        )
        return replace(candidate, severity=policy_result.override_severity)
    return candidate
