"""Confidence aggregation strategies.

Combines multiple evaluator results into a single final verdict — this IS
the "ensemble" combination step (a list of independent Evaluators plus one
ConfidenceAggregator is the ensemble-evaluation pattern; there is no
separate "EnsembleAggregator" type, since that would just duplicate this
protocol's job under a different name).

WeightedAverageAggregator: default production strategy.
MajorityVoteAggregator: simple vote-counting strategy.
BayesianConfidenceAggregator: treats each evaluator as an independent
noisy sensor and combines them via Bayesian updating — the "Bayesian
confidence" strategy referenced in the evaluation intelligence roadmap.
Custom enterprise strategies plug in via the ConfidenceAggregator protocol.
"""

from __future__ import annotations

from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationOutcome,
    EvaluatorResult,
)


class WeightedAverageAggregator:
    """Aggregates evaluator results using weighted confidence averaging.

    Strategy:
    1. Group results by outcome
    2. For each outcome group, compute weighted confidence
    3. The outcome with highest total weighted confidence wins
    4. Final confidence is the winning group's average confidence

    Weights can be assigned per evaluator name.
    Default weight: 1.0 for all evaluators.
    """

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self._weights = weights or {}
        self._default_weight = 1.0

    def aggregate(
        self, results: list[EvaluatorResult]
    ) -> AggregatedEvaluation:
        """Combine evaluator results into a final evaluation."""
        if not results:
            return AggregatedEvaluation(
                step_id="",
                attack_id="",
                outcome=EvaluationOutcome.INCONCLUSIVE,
                confidence=0.0,
                evaluator_results=(),
                reasoning="No evaluator results to aggregate",
            )

        # Filter out ERROR results for scoring (they don't vote)
        voting_results = [
            r for r in results if r.outcome != EvaluationOutcome.ERROR
        ]

        if not voting_results:
            return AggregatedEvaluation(
                step_id="",
                attack_id="",
                outcome=EvaluationOutcome.ERROR,
                confidence=1.0,
                evaluator_results=tuple(results),
                reasoning="All evaluators returned errors",
            )

        # Calculate weighted scores per outcome
        outcome_scores: dict[EvaluationOutcome, float] = {}
        outcome_counts: dict[EvaluationOutcome, int] = {}

        for r in voting_results:
            weight = self._weights.get(r.evaluator_name, self._default_weight)
            score = r.confidence * weight
            outcome_scores[r.outcome] = outcome_scores.get(r.outcome, 0) + score
            outcome_counts[r.outcome] = outcome_counts.get(r.outcome, 0) + 1

        # Winning outcome has highest total weighted score
        winning_outcome = max(outcome_scores, key=outcome_scores.get)  # type: ignore[arg-type]

        # Final confidence: average of winning evaluators' confidence
        winning_confidences = [
            r.confidence for r in voting_results
            if r.outcome == winning_outcome
        ]
        final_confidence = (
            sum(winning_confidences) / len(winning_confidences)
            if winning_confidences
            else 0.0
        )

        # Build reasoning
        total_evaluators = len(voting_results)
        agreeing = outcome_counts.get(winning_outcome, 0)
        reasoning = (
            f"{agreeing}/{total_evaluators} evaluators agree: {winning_outcome.value}"
        )

        return AggregatedEvaluation(
            step_id="",
            attack_id="",
            outcome=winning_outcome,
            confidence=round(final_confidence, 3),
            evaluator_results=tuple(results),
            reasoning=reasoning,
        )


class MajorityVoteAggregator:
    """Simple majority vote — outcome with most evaluator votes wins.

    Ties are resolved as INCONCLUSIVE.
    Confidence is the proportion of evaluators that agree.
    """

    def aggregate(
        self, results: list[EvaluatorResult]
    ) -> AggregatedEvaluation:
        """Aggregate by majority vote."""
        if not results:
            return AggregatedEvaluation(
                step_id="", attack_id="",
                outcome=EvaluationOutcome.INCONCLUSIVE,
                confidence=0.0,
                evaluator_results=(),
                reasoning="No results",
            )

        voting = [r for r in results if r.outcome != EvaluationOutcome.ERROR]
        if not voting:
            return AggregatedEvaluation(
                step_id="", attack_id="",
                outcome=EvaluationOutcome.ERROR,
                confidence=1.0,
                evaluator_results=tuple(results),
                reasoning="All evaluators errored",
            )

        # Count votes
        votes: dict[EvaluationOutcome, int] = {}
        for r in voting:
            votes[r.outcome] = votes.get(r.outcome, 0) + 1

        max_votes = max(votes.values())
        winners = [o for o, v in votes.items() if v == max_votes]

        if len(winners) > 1:
            outcome = EvaluationOutcome.INCONCLUSIVE
            confidence = max_votes / len(voting)
            reasoning = f"Tie between: {[w.value for w in winners]}"
        else:
            outcome = winners[0]
            confidence = max_votes / len(voting)
            reasoning = f"Majority ({max_votes}/{len(voting)}): {outcome.value}"

        return AggregatedEvaluation(
            step_id="", attack_id="",
            outcome=outcome,
            confidence=round(confidence, 3),
            evaluator_results=tuple(results),
            reasoning=reasoning,
        )


class BayesianConfidenceAggregator:
    """Combines evaluator results via Bayesian updating.

    Each evaluator is treated as an independent noisy sensor reporting a
    belief P(outcome) = confidence for its chosen outcome, with the
    remaining probability mass spread uniformly over the other outcomes.
    Starting from a uniform prior over {VULNERABLE, SECURE, INCONCLUSIVE},
    each evaluator's report is folded in as a Bayesian update
    (posterior proportional to prior * likelihood), normalized after each step.

    This differs from WeightedAverageAggregator in a way that matters in
    practice: two evaluators independently reporting "vulnerable" at 0.6
    confidence produce *higher* combined confidence here than a simple
    average would give (0.6), because independent corroboration is
    genuine evidence — exactly the effect Bayesian combination is
    supposed to capture. A single dissenting high-confidence evaluator
    can also swing the posterior harder than a plain average would.

    ERROR results are excluded from the update (an errored evaluator
    contributes no evidence either way), matching the other aggregators'
    convention.
    """

    _CANDIDATE_OUTCOMES = (
        EvaluationOutcome.VULNERABLE,
        EvaluationOutcome.SECURE,
        EvaluationOutcome.INCONCLUSIVE,
    )

    def aggregate(
        self, results: list[EvaluatorResult]
    ) -> AggregatedEvaluation:
        if not results:
            return AggregatedEvaluation(
                step_id="", attack_id="",
                outcome=EvaluationOutcome.INCONCLUSIVE,
                confidence=0.0,
                evaluator_results=(),
                reasoning="No evaluator results to aggregate",
            )

        voting = [r for r in results if r.outcome != EvaluationOutcome.ERROR]
        if not voting:
            return AggregatedEvaluation(
                step_id="", attack_id="",
                outcome=EvaluationOutcome.ERROR,
                confidence=1.0,
                evaluator_results=tuple(results),
                reasoning="All evaluators returned errors",
            )

        n = len(self._CANDIDATE_OUTCOMES)
        posterior: dict[EvaluationOutcome, float] = {
            outcome: 1.0 / n for outcome in self._CANDIDATE_OUTCOMES
        }

        for r in voting:
            reported_outcome = (
                r.outcome if r.outcome in self._CANDIDATE_OUTCOMES
                else EvaluationOutcome.INCONCLUSIVE
            )
            # Likelihood: this evaluator assigns `confidence` mass to its
            # reported outcome and spreads the remainder uniformly.
            remainder = (1.0 - r.confidence) / (n - 1) if n > 1 else 0.0
            for outcome in self._CANDIDATE_OUTCOMES:
                likelihood = r.confidence if outcome == reported_outcome else remainder
                posterior[outcome] *= max(likelihood, 1e-6)  # avoid zeroing out

            total = sum(posterior.values())
            if total > 0:
                posterior = {o: p / total for o, p in posterior.items()}

        winning_outcome = max(posterior, key=lambda o: posterior[o])
        final_confidence = posterior[winning_outcome]

        reasoning = (
            f"Bayesian posterior after {len(voting)} evaluator(s): "
            + ", ".join(f"{o.value}={p:.2f}" for o, p in posterior.items())
        )

        return AggregatedEvaluation(
            step_id="", attack_id="",
            outcome=winning_outcome,
            confidence=round(final_confidence, 3),
            evaluator_results=tuple(results),
            reasoning=reasoning,
        )
