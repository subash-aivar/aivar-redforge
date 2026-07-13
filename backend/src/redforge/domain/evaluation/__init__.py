"""Response Evaluation Intelligence bounded context.

Determines whether an executed AI attack actually succeeded — the
decision-making intelligence layer of RedForge. Layered on top of the
existing, already-complete `application/runtime/evaluation/` engine
(see value_objects.py's module docstring for the full architecture
rationale) rather than duplicating it.

Public API:
    - EvaluationResult: Aggregate root — the immutable output of evaluation.
    - EvaluationEngine: Default EvaluationEngineProtocol implementation
      (the 8-stage pipeline orchestrator).
    - Protocols: EvaluationEngineProtocol, EvaluatorProtocol,
      EvaluationPipelineProtocol, EvidenceNormalizer, ConfidenceCalculator,
      RiskScorer, FindingBuilder, RemediationAdvisor, KnowledgeProjector.
    - Value objects: AttackOutcome, EvaluationEvidence, RiskContribution,
      RecommendedFinding, RecommendedSeverity, RecommendedRemediation, etc.
"""

from redforge.domain.evaluation.entity import EvaluationResult
from redforge.domain.evaluation.pipeline import EvaluationEngine
from redforge.domain.evaluation.protocols import (
    ConfidenceCalculator,
    EvaluationEngineProtocol,
    EvaluationPipelineProtocol,
    EvaluatorProtocol,
    EvidenceNormalizer,
    FindingBuilder,
    KnowledgeProjector,
    RemediationAdvisor,
    RiskScorer,
)
from redforge.domain.evaluation.repository import EvaluationResultRepository
from redforge.domain.evaluation.value_objects import (
    AttackOutcome,
    Confidence,
    EvaluationEvidence,
    EvaluationStage,
    EvaluationStatus,
    NormalizedEvidence,
    RecommendedFinding,
    RecommendedRemediation,
    RecommendedSeverity,
    RiskContribution,
)

__all__ = [
    "AttackOutcome",
    "Confidence",
    "ConfidenceCalculator",
    "EvaluationEngine",
    "EvaluationEngineProtocol",
    "EvaluationEvidence",
    "EvaluationPipelineProtocol",
    "EvaluationResult",
    "EvaluationResultRepository",
    "EvaluationStage",
    "EvaluationStatus",
    "EvaluatorProtocol",
    "EvidenceNormalizer",
    "FindingBuilder",
    "KnowledgeProjector",
    "NormalizedEvidence",
    "RecommendedFinding",
    "RecommendedRemediation",
    "RecommendedSeverity",
    "RemediationAdvisor",
    "RiskContribution",
    "RiskScorer",
]
