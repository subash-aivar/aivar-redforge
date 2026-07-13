"""Confidence calibration — ConfidenceCalculator implementations.

Distinct from aggregators.py (which decides *what* the verdict is):
these implementations assess *how likely that verdict is to be wrong*,
producing a RiskAssessment consumed by ExplainabilityProvider.
"""

from __future__ import annotations

from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationContext,
    EvaluationOutcome,
    RiskAssessment,
)


class HeuristicConfidenceCalculator:
    """Reference ConfidenceCalculator: derives risk from confidence and
    evaluator agreement.

    Rationale:
    - Low raw confidence → both FP and FN risk rise (the pipeline itself
      isn't sure).
    - Low agreement_ratio (evaluators disagree) → risk rises regardless
      of the winning confidence number, because a single strong outlier
      evaluator can otherwise mask real disagreement.
    - A single-evaluator verdict is inherently less calibrated than a
      multi-evaluator consensus — the risk floor is raised when only
      one evaluator voted.

    This is a defensible statistical heuristic, not a placeholder — it
    is the same "confidence + inter-rater agreement" calibration logic
    used across ensemble ML systems. Enterprise customers wanting
    calibration based on historical accuracy per evaluator (Bayesian
    updating from labeled outcomes) should implement ConfidenceCalculator
    against their own labeled-finding feedback loop; the protocol makes
    that a drop-in replacement.
    """

    def assess(
        self, evaluation: AggregatedEvaluation, context: EvaluationContext
    ) -> RiskAssessment:
        confidence = evaluation.confidence
        agreement = evaluation.agreement_ratio
        single_evaluator_penalty = 0.15 if evaluation.evaluator_count <= 1 else 0.0

        # Uncertainty rises as confidence falls and as evaluators disagree.
        uncertainty = (1.0 - confidence) * 0.6 + (1.0 - agreement) * 0.4
        uncertainty = min(1.0, uncertainty + single_evaluator_penalty)

        if evaluation.outcome == EvaluationOutcome.VULNERABLE:
            false_positive_risk = round(uncertainty, 3)
            false_negative_risk = round(uncertainty * 0.4, 3)
            rationale = (
                f"VULNERABLE verdict at {confidence:.0%} confidence with "
                f"{agreement:.0%} evaluator agreement. False-positive risk "
                f"reflects residual uncertainty in the vulnerable call; "
                f"false-negative risk is secondary once a vulnerability is "
                f"already flagged."
            )
        elif evaluation.outcome == EvaluationOutcome.SECURE:
            false_positive_risk = round(uncertainty * 0.4, 3)
            false_negative_risk = round(uncertainty, 3)
            rationale = (
                f"SECURE verdict at {confidence:.0%} confidence with "
                f"{agreement:.0%} evaluator agreement. False-negative risk "
                f"reflects the chance a real vulnerability was missed."
            )
        else:
            # ERROR / INCONCLUSIVE: both risks are elevated — the pipeline
            # has not actually reached a security verdict.
            false_positive_risk = round(0.5 + uncertainty * 0.25, 3)
            false_negative_risk = round(0.5 + uncertainty * 0.25, 3)
            rationale = (
                f"Outcome '{evaluation.outcome.value}' did not reach a "
                f"pass/fail verdict — both false-positive and "
                f"false-negative risk are elevated by default."
            )

        if evaluation.evaluator_count <= 1:
            rationale += " Single-evaluator verdict: no cross-validation available."

        return RiskAssessment(
            false_positive_risk=min(1.0, false_positive_risk),
            false_negative_risk=min(1.0, false_negative_risk),
            rationale=rationale,
        )
