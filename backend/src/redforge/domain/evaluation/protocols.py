"""Protocols for the Response Evaluation Intelligence pipeline.

Given: ExecutionResult/Evidence, AttackDefinition, AttackPlan, Target,
Provider, Conversation, ExecutionMetadata.
Produces: EvaluationResult.

Pipeline: Evidence Normalization -> Rule Evaluation -> Semantic
Evaluation -> Pattern Matching -> Risk Scoring -> Confidence
Calculation -> Finding Recommendation -> Knowledge Graph Projection.

Every stage is a Protocol; EvaluationEngine (pipeline.py) depends on
none of the concrete implementations directly. No switch statements:
outcome determination in EvaluationEngine is priority-ordered rule
evaluation over `AttackOutcome` values, not a dispatch table over
evaluator identity.

Real detection/scoring/remediation logic is NOT reimplemented here —
see application/evaluation_adapters.py, which wraps the existing,
already-complete `application/runtime/evaluation/` engine
(KeywordEvaluator, PatternEvaluator, RuleEvaluator, SemanticEvaluator,
DefaultFindingGenerator, HeuristicConfidenceCalculator,
StaticRemediationProvider) behind these Protocols.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.evaluation.entity import EvaluationResult
    from redforge.domain.evaluation.value_objects import (
        AttackOutcome,
        Confidence,
        EvaluationEvidence,
        NormalizedEvidence,
        RecommendedFinding,
        RecommendedRemediation,
        RiskContribution,
    )
    from redforge.domain.evidence.entity import Evidence
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class EvidenceNormalizer(Protocol):
    """Stage 1: converts a raw Evidence record into the uniform
    NormalizedEvidence shape every evaluator consumes, regardless of
    whether the underlying source was a single-turn request/response,
    a multi-turn Conversation, or a batch ExecutionResult."""

    def normalize(self, evidence: Evidence) -> NormalizedEvidence:
        ...


@runtime_checkable
class EvaluatorProtocol(Protocol):
    """One pluggable evaluator — Rule, Semantic, Pattern, or a future/
    custom enterprise evaluator (LLMJudgeEvaluator, EmbeddingEvaluator,
    PolicyEvaluator, etc.). Stateless: given normalized evidence,
    produces one independent opinion. Multiple evaluators run per stage;
    EvaluationEngine collects all their opinions into the evaluation
    trail before determining an outcome — no single evaluator decides
    the verdict alone.
    """

    @property
    def name(self) -> str:
        ...

    async def evaluate(self, evidence: NormalizedEvidence) -> EvaluationEvidence:
        ...


@runtime_checkable
class EvaluationPipelineProtocol(Protocol):
    """Runs a configured set of evaluators (typically all of Rule +
    Semantic + Pattern) against one NormalizedEvidence and returns the
    combined trail — the seam a caller uses to swap in an entirely
    different evaluation strategy (e.g. a single LLM-judge call that
    internally does rule+semantic+pattern reasoning at once) without
    EvaluationEngine needing to know the difference.
    """

    async def run(self, evidence: NormalizedEvidence) -> tuple[EvaluationEvidence, ...]:
        ...


@runtime_checkable
class RiskScorer(Protocol):
    """Stage 5: produces this evaluation's contribution to the
    platform's overall risk picture — application.evaluation_adapters
    converts the result into application.risk_engine.RiskFactor for
    RiskCorrelationEngine, rather than this domain module reimplementing
    CVSS-style scoring."""

    def score(
        self,
        outcome: AttackOutcome,
        trail: tuple[EvaluationEvidence, ...],
        attack: AttackDefinition,
    ) -> RiskContribution:
        ...


@runtime_checkable
class ConfidenceCalculator(Protocol):
    """Stage 6: produces the EvaluationResult's overall Confidence from
    the full evaluation trail — a cross-stage aggregation concern,
    distinct from application.runtime.evaluation.contracts.ConfidenceCalculator
    (which assesses false-positive/false-negative calibration risk on an
    already-decided verdict, a narrower and different question — see
    value_objects.py's module docstring for the full disambiguation).
    """

    def calculate(self, trail: tuple[EvaluationEvidence, ...]) -> Confidence:
        ...


@runtime_checkable
class FindingBuilder(Protocol):
    """Stage 7: builds a RecommendedFinding from an outcome that
    warrants one (SUCCESS/PARTIAL_SUCCESS) — returns None for outcomes
    that don't (FAILURE/INCONCLUSIVE/ERROR)."""

    def build(
        self,
        outcome: AttackOutcome,
        trail: tuple[EvaluationEvidence, ...],
        attack: AttackDefinition,
    ) -> RecommendedFinding | None:
        ...


@runtime_checkable
class RemediationAdvisor(Protocol):
    """Stage 7 (continued): recommends a fix for a RecommendedFinding.
    Only invoked when FindingBuilder actually produced a finding."""

    def advise(
        self,
        outcome: AttackOutcome,
        attack: AttackDefinition,
        finding: RecommendedFinding,
    ) -> RecommendedRemediation | None:
        ...


@runtime_checkable
class KnowledgeProjector(Protocol):
    """Stage 8: projects a finished EvaluationResult into the platform's
    Knowledge Graph (application/knowledge_graph.py) — a side-effecting
    Protocol whose concrete implementation lives in the application
    layer (this domain module cannot import the graph, per ADR-0001),
    mirroring Sprint 13's AttackKnowledgeGraphProjector pattern.
    """

    def project(self, result: EvaluationResult) -> None:
        ...


@runtime_checkable
class EvaluationEngineProtocol(Protocol):
    """The top-level pipeline orchestrator: Evidence -> EvaluationResult."""

    async def evaluate(
        self,
        evidence: Evidence,
        attack: AttackDefinition,
        target_id: EntityId,
        organization_id: EntityId,
        *,
        attack_plan_id: EntityId | None = None,
    ) -> EvaluationResult:
        ...
