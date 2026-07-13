"""Evaluation Engine — intelligence layer for AI security assessment.

Consumes runtime evidence (StepEvidence) and produces structured
evaluation results through a multi-evaluator pipeline.

Architecture:
- Evaluator protocol (independently replaceable)
- EvaluationPipeline (configurable evaluator ordering)
- ConfidenceAggregator (combine multiple evaluator opinions)
- FindingCandidateGenerator (bridge to existing Findings domain)

Implements the existing ResponseClassifier protocol so it integrates
seamlessly with the runtime orchestrator as a drop-in replacement.
"""
