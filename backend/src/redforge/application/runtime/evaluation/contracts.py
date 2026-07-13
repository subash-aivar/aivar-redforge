"""Evaluation Engine protocols.

Every evaluator, aggregation strategy, confidence calculator, and
explainability provider is protocol-based. Enterprise customers can
implement proprietary evaluators, aggregators, or explainability
providers without modifying RedForge core — they only need to satisfy
the relevant Protocol below.

Implemented evaluators (see evaluators.py, semantic.py, llm_judge.py):
- KeywordEvaluator, PatternEvaluator, RuleEvaluator (lexical/structural)
- SemanticEvaluator (similarity-based, pluggable SemanticSimilarityProvider)
- LLMJudgeEvaluator (provider-independent, pluggable LLMJudgeProvider)

Future evaluators (no code changes needed — implement Evaluator):
- PolicyEvaluator
- SafetyEvaluator
- GroundingEvaluator
- HallucinationEvaluator
- PromptLeakageEvaluator
- ToolAbuseEvaluator
- AgentBehaviorEvaluator
- RAGEvaluator
- MCPEvaluator
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationContext,
    EvaluationIntelligence,
    EvaluatorResult,
    FindingCandidate,
    RiskAssessment,
)


@runtime_checkable
class Evaluator(Protocol):
    """Protocol for a single evaluator.

    An evaluator inspects evidence and produces an independent opinion.
    Multiple evaluators run in a pipeline; their results are aggregated.

    Stateless: receives context, returns result. No side effects.
    """

    @property
    def name(self) -> str:
        """Unique evaluator name for identification in results."""
        ...

    async def evaluate(self, context: EvaluationContext) -> EvaluatorResult:
        """Evaluate evidence and produce a result."""
        ...


@runtime_checkable
class ConfidenceAggregator(Protocol):
    """Combines multiple evaluator results into a final verdict.

    Strategies:
    - WeightedAverage (default)
    - UnanimousAgreement
    - MajorityVote
    - Custom enterprise strategies
    """

    def aggregate(
        self, results: list[EvaluatorResult]
    ) -> AggregatedEvaluation:
        """Combine evaluator results into a single evaluation."""
        ...


@runtime_checkable
class FindingCandidateGenerator(Protocol):
    """Converts aggregated evaluations into finding candidates.

    Finding candidates are passed to the existing Findings domain
    for persistence. This generator does NOT create domain entities.
    """

    def generate(
        self, evaluation: AggregatedEvaluation, context: EvaluationContext
    ) -> FindingCandidate | None:
        """Generate a finding candidate if the evaluation warrants one.

        Returns None if no finding should be created (e.g., SECURE result).
        """
        ...


@runtime_checkable
class ConfidenceCalculator(Protocol):
    """Assesses calibration risk for an already-aggregated evaluation.

    Distinct responsibility from ConfidenceAggregator: the aggregator
    decides *which outcome wins and how confident the pipeline is in it*.
    ConfidenceCalculator answers a different question — *how likely is
    this specific verdict to be wrong, and in which direction* (false
    positive vs false negative)? This is calibration/risk assessment,
    not voting, so it is kept as its own protocol rather than folded
    into ConfidenceAggregator (which would conflate two responsibilities
    and make either one harder to replace independently).

    Strategies: heuristic (confidence + evaluator agreement), historical
    calibration (per-evaluator track record), LLM self-assessment.
    """

    def assess(
        self, evaluation: AggregatedEvaluation, context: EvaluationContext
    ) -> RiskAssessment:
        """Produce a false-positive/false-negative risk assessment."""
        ...


@runtime_checkable
class ExplainabilityProvider(Protocol):
    """Synthesizes an EvaluationIntelligence from an AggregatedEvaluation.

    This is the "why" layer: matched security frameworks (OWASP, MITRE
    ATLAS), matched security objectives / threat coverage tags,
    supporting evidence, a reasoning summary, a recommended remediation,
    a calibration RiskAssessment, and a full ExplainabilityTrace an
    auditor can read decision-by-decision.

    Runs after aggregation, before finding-candidate generation — it does
    NOT decide pass/fail (that's Evaluator + ConfidenceAggregator's job);
    it only explains a verdict that has already been reached.
    """

    def explain(
        self,
        evaluation: AggregatedEvaluation,
        context: EvaluationContext,
    ) -> EvaluationIntelligence:
        """Produce the full explainability record for one evaluation."""
        ...
