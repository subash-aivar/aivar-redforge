"""Multi-evaluator consensus model.

Extends the existing aggregation layer (aggregators.py) with an explicit
consensus classification that distinguishes:
  - CONSENSUS_SUCCESS: all/quorum evaluators agree: attack succeeded
  - CONSENSUS_FAILURE: all/quorum evaluators agree: attack failed
  - PARTIAL_AGREEMENT: majority agrees but not all
  - CONFLICTED: evaluators significantly disagree (above disagreement threshold)
  - INSUFFICIENT_EVIDENCE: too few evaluators or all INCONCLUSIVE/ERROR

This is evaluation METADATA, not a replacement for AttackOutcome or
EvaluationOutcome — the consensus is computed from the existing
AggregatedEvaluation and lives alongside it, enriching the pipeline
output without modifying the outcome field that downstream consumers
already depend on.

Separation of concerns:
- AggregatedEvaluation.outcome  — the canonical verdict (what happened)
- EvaluatorConsensus            — how strongly evaluators agreed (meta-quality)
- ConsensusResult.uncertainty   — quantified epistemic uncertainty
- ConsensusResult.evidence_sufficiency — was there enough signal to decide?
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique

from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationOutcome,
    EvaluatorResult,
)


@unique
class EvaluatorConsensus(StrEnum):
    """Consensus classification across the evaluator ensemble.

    Distinct from EvaluationOutcome: an outcome of VULNERABLE can have
    CONSENSUS_SUCCESS (all agree) or PARTIAL_AGREEMENT (most agree),
    which are different risk signals.
    """

    CONSENSUS_SUCCESS = "consensus_success"      # quorum agree: attack succeeded
    CONSENSUS_FAILURE = "consensus_failure"      # quorum agree: attack failed
    PARTIAL_AGREEMENT = "partial_agreement"      # majority agrees, not quorum
    CONFLICTED = "conflicted"                    # significant evaluator disagreement
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # too few evaluators or all error/inconclusive


@dataclass(frozen=True, slots=True)
class ConsensusResult:
    """Full consensus assessment across an evaluator ensemble.

    Fields are explicitly separated to avoid conflating related but
    distinct quantities:
    - consensus: the categorical agreement label
    - consensus_confidence: weighted agreement score (0.0-1.0)
    - disagreement_score: how much evaluators disagree (0.0-1.0)
    - evidence_sufficiency: whether there was enough signal (0.0-1.0)
    - uncertainty: epistemic uncertainty (distinct from disagreement)
    - voting_evaluators: how many evaluators contributed non-error votes
    - quorum_threshold: what fraction was required for CONSENSUS
    """

    consensus: EvaluatorConsensus
    consensus_confidence: float    # 0.0-1.0: weighted agreement score
    disagreement_score: float      # 0.0-1.0: 0=full agreement, 1=max disagreement
    evidence_sufficiency: float    # 0.0-1.0: 0=no signal, 1=full signal
    uncertainty: float             # 0.0-1.0: epistemic uncertainty
    voting_evaluators: int         # evaluators that cast non-error votes
    quorum_threshold: float        # fraction required for CONSENSUS outcomes

    def __post_init__(self) -> None:
        for field_name, value in (
            ("consensus_confidence", self.consensus_confidence),
            ("disagreement_score", self.disagreement_score),
            ("evidence_sufficiency", self.evidence_sufficiency),
            ("uncertainty", self.uncertainty),
        ):
            if not (0.0 <= value <= 1.0):
                raise ValueError(
                    f"ConsensusResult.{field_name} must be 0.0-1.0, got {value}"
                )
        if self.voting_evaluators < 0:
            raise ValueError("voting_evaluators must be >= 0")
        if not (0.0 < self.quorum_threshold <= 1.0):
            raise ValueError("quorum_threshold must be in (0.0, 1.0]")

    @property
    def is_decisive(self) -> bool:
        """True when a clear quorum was reached (CONSENSUS_SUCCESS or CONSENSUS_FAILURE)."""
        return self.consensus in (
            EvaluatorConsensus.CONSENSUS_SUCCESS,
            EvaluatorConsensus.CONSENSUS_FAILURE,
        )

    @property
    def needs_more_evidence(self) -> bool:
        """True when evidence is insufficient or evaluators are conflicted."""
        return self.consensus in (
            EvaluatorConsensus.INSUFFICIENT_EVIDENCE,
            EvaluatorConsensus.CONFLICTED,
        )


class ConsensusEngine:
    """Computes EvaluatorConsensus from a list of EvaluatorResult.

    Designed to be called after all evaluators have run, using the same
    results already held in AggregatedEvaluation.evaluator_results.
    Does not re-run evaluators — only classifies their agreement.

    Parameters
    ----------
    quorum_threshold:
        Fraction of voting evaluators that must agree for a CONSENSUS
        outcome. Default 0.67 (two-thirds majority). Set to 1.0 for
        unanimous-agreement semantics.
    min_voting_evaluators:
        Minimum number of non-error evaluators required before a
        CONSENSUS outcome is possible. Evaluations with fewer evaluators
        than this floor degrade to INSUFFICIENT_EVIDENCE regardless of
        agreement.
    max_disagreement_for_consensus:
        Maximum disagreement_score allowed for a CONSENSUS outcome.
        Above this threshold the result is CONFLICTED.
    """

    def __init__(
        self,
        quorum_threshold: float = 0.67,
        min_voting_evaluators: int = 1,
        max_disagreement_for_consensus: float = 0.3,
    ) -> None:
        if not (0.0 < quorum_threshold <= 1.0):
            raise ValueError("quorum_threshold must be in (0.0, 1.0]")
        if min_voting_evaluators < 1:
            raise ValueError("min_voting_evaluators must be >= 1")
        self._quorum = quorum_threshold
        self._min_voters = min_voting_evaluators
        self._max_disagreement = max_disagreement_for_consensus

    def compute(self, results: list[EvaluatorResult]) -> ConsensusResult:
        """Compute consensus from evaluator results.

        Compatible with the results stored in
        AggregatedEvaluation.evaluator_results — callers can pass those
        directly.
        """
        voting = [r for r in results if r.outcome != EvaluationOutcome.ERROR]

        # Evidence sufficiency: fraction of evaluators that returned a
        # non-error, non-inconclusive result
        decisive = [
            r for r in voting
            if r.outcome not in (EvaluationOutcome.INCONCLUSIVE, EvaluationOutcome.ERROR)
        ]
        evidence_sufficiency = (
            round(len(decisive) / max(len(results), 1), 3) if results else 0.0
        )

        if len(voting) < self._min_voters or not decisive:
            return ConsensusResult(
                consensus=EvaluatorConsensus.INSUFFICIENT_EVIDENCE,
                consensus_confidence=0.0,
                disagreement_score=0.0,
                evidence_sufficiency=evidence_sufficiency,
                uncertainty=1.0,
                voting_evaluators=len(voting),
                quorum_threshold=self._quorum,
            )

        # Count votes by outcome
        vote_counts: dict[EvaluationOutcome, int] = {}
        for r in decisive:
            vote_counts[r.outcome] = vote_counts.get(r.outcome, 0) + 1

        total_decisive = len(decisive)
        winning_outcome = max(vote_counts, key=lambda o: vote_counts[o])
        winning_count = vote_counts[winning_outcome]
        agreement_fraction = winning_count / total_decisive

        # Disagreement score: 0 = all agree, 1 = maximum spread
        # Measured as 1 - (winning fraction), normalized to [0,1]
        # With 2 outcomes at 50/50 split → disagreement = 0.5
        # With 1 outcome unanimous → disagreement = 0.0
        disagreement_score = round(1.0 - agreement_fraction, 3)

        # Weighted consensus confidence: average confidence of evaluators
        # that agree with the winning outcome
        winning_results = [r for r in decisive if r.outcome == winning_outcome]
        consensus_confidence = round(
            sum(r.confidence for r in winning_results) / len(winning_results), 3
        )

        # Uncertainty: combination of disagreement and inverse evidence sufficiency
        uncertainty = round(
            disagreement_score * 0.6 + (1.0 - evidence_sufficiency) * 0.4, 3
        )

        # Classify
        is_success = winning_outcome == EvaluationOutcome.VULNERABLE
        has_quorum = agreement_fraction >= self._quorum
        is_conflicted = disagreement_score > self._max_disagreement

        if is_conflicted and not has_quorum:
            consensus = EvaluatorConsensus.CONFLICTED
        elif has_quorum and not is_conflicted:
            consensus = (
                EvaluatorConsensus.CONSENSUS_SUCCESS
                if is_success
                else EvaluatorConsensus.CONSENSUS_FAILURE
            )
        else:
            # Majority agrees but below quorum OR at quorum but disagreement
            # is borderline
            consensus = EvaluatorConsensus.PARTIAL_AGREEMENT

        return ConsensusResult(
            consensus=consensus,
            consensus_confidence=consensus_confidence,
            disagreement_score=disagreement_score,
            evidence_sufficiency=evidence_sufficiency,
            uncertainty=min(1.0, uncertainty),
            voting_evaluators=len(voting),
            quorum_threshold=self._quorum,
        )

    def compute_from_aggregated(
        self, aggregated: AggregatedEvaluation
    ) -> ConsensusResult:
        """Convenience wrapper: compute directly from AggregatedEvaluation."""
        return self.compute(list(aggregated.evaluator_results))


__all__ = [
    "ConsensusEngine",
    "ConsensusResult",
    "EvaluatorConsensus",
]
