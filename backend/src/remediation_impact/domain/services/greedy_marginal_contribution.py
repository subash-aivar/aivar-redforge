"""GreedyMarginalContribution — frozen Finalization D5 algorithm."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from remediation_impact.domain.exceptions.domain_exceptions import EmptyCandidateSet
from remediation_impact.domain.value_objects.enums import (
    ApproximationMode,
    SimulationAlgorithm,
)
from remediation_impact.domain.value_objects.simulation_vos import (
    PlanStep,
    RemediationCandidate,
    SimulationResult,
)

if TYPE_CHECKING:
    from datetime import datetime

MIN_DELTA_THRESHOLD = 0.01
DEFAULT_TOP_K = 200
FULL_COMPUTATION_THRESHOLD = 100_000
DEFAULT_MAX_SAMPLE_SIZE = 20_000


def derive_simulation_seed(plan_generated_at: datetime) -> int:
    return int(plan_generated_at.timestamp()) % (2**32)


def portfolio_weighted_sample(
    scores: dict[str, float],
    sample_size: int,
    seed: int,
) -> dict[str, float]:
    """Deterministic portfolio-weighted sampling (60/30/10 high/mid/low)."""
    if sample_size >= len(scores) or not scores:
        return dict(scores)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    n = len(ranked)
    q = max(1, n // 4)
    high = ranked[:q]
    low = ranked[-q:] if q < n else []
    mid = ranked[q : n - q] if n > 2 * q else ranked[q:]
    rng = random.Random(seed)
    high_n = min(len(high), max(1, int(sample_size * 0.6)))
    mid_n = min(len(mid), max(0, int(sample_size * 0.3)))
    low_n = min(len(low), max(0, sample_size - high_n - mid_n))
    picked = (
        rng.sample(high, high_n)
        + (rng.sample(mid, mid_n) if mid and mid_n else [])
        + (rng.sample(low, low_n) if low and low_n else [])
    )
    return dict(picked)


def _candidate_estimated_impact(candidate: RemediationCandidate, scores: dict[str, float]) -> float:
    total = 0.0
    for asset in candidate.affected_asset_refs:
        total += scores.get(asset, 0.0)
    return total + candidate.estimated_base_reduction


def _marginal_delta(
    candidate: RemediationCandidate,
    working_scores: dict[str, float],
) -> float:
    """Estimate marginal reduction: remove estimated_base_reduction from affected assets."""
    delta = 0.0
    reduction = max(0.0, candidate.estimated_base_reduction)
    if reduction <= 0.0 and candidate.affected_asset_refs:
        # Fallback: remove 20% of current score on affected assets
        for asset in candidate.affected_asset_refs:
            current = working_scores.get(asset, 0.0)
            delta += current * 0.2
        return delta
    for asset in candidate.affected_asset_refs:
        current = working_scores.get(asset, 0.0)
        applied = min(current, reduction)
        delta += applied
    return delta


def _apply_candidate(candidate: RemediationCandidate, working_scores: dict[str, float]) -> None:
    reduction = max(0.0, candidate.estimated_base_reduction)
    for asset in candidate.affected_asset_refs:
        current = working_scores.get(asset, 0.0)
        if reduction > 0.0:
            working_scores[asset] = max(0.0, current - reduction)
        else:
            working_scores[asset] = max(0.0, current * 0.8)


def run_greedy_marginal_contribution(
    *,
    candidates: list[RemediationCandidate],
    current_exposure_scores: dict[str, float],
    plan_budget: int,
    top_k: int = DEFAULT_TOP_K,
    sample_size: int | None = None,
    plan_generated_at: datetime,
    score_input_version: int,
    business_impact_factor: float = 1000.0,
) -> SimulationResult:
    if not candidates:
        raise EmptyCandidateSet("candidate_remediations must be non-empty")
    seed = derive_simulation_seed(plan_generated_at)
    total_assets = len(current_exposure_scores)
    working_full = dict(current_exposure_scores)

    if sample_size is None and total_assets > FULL_COMPUTATION_THRESHOLD:
        sample_size = min(DEFAULT_MAX_SAMPLE_SIZE, total_assets)

    if sample_size is not None and sample_size < total_assets:
        working = portfolio_weighted_sample(working_full, sample_size, seed)
        approx = ApproximationMode.SAMPLED.value
        scale = total_assets / max(1, len(working))
        approx_label = f"Sampled ({len(working)}/{total_assets})"
    else:
        working = dict(working_full)
        approx = ApproximationMode.EXACT.value
        scale = 1.0
        approx_label = ApproximationMode.EXACT.value
        sample_size = len(working)

    ranked_pool = sorted(
        candidates,
        key=lambda c: _candidate_estimated_impact(c, working),
        reverse=True,
    )[: max(1, top_k)]
    remaining = list(ranked_pool)
    selected: list[PlanStep] = []
    baseline_sum = sum(working.values())

    for _ in range(max(1, plan_budget)):
        if not remaining:
            break
        best: RemediationCandidate | None = None
        best_delta = 0.0
        for candidate in remaining:
            delta = _marginal_delta(candidate, working)
            if delta > best_delta:
                best_delta = delta
                best = candidate
        if best is None or best_delta < MIN_DELTA_THRESHOLD:
            break
        selected.append(
            PlanStep(
                remediation_id=best.remediation_id,
                marginal_delta=best_delta * scale,
                affected_asset_refs=best.affected_asset_refs,
                rank=len(selected) + 1,
            )
        )
        _apply_candidate(best, working)
        remaining.remove(best)

    projected = (baseline_sum - sum(working.values())) * scale
    estimated_business_impact = projected * business_impact_factor
    return SimulationResult(
        plan_steps=tuple(selected),
        projected_exposure_reduction=projected,
        algorithm=SimulationAlgorithm.GREEDY_MARGINAL_CONTRIBUTION.value,
        top_k=top_k,
        sample_size=len(working),
        approximation_mode=(approx_label if approx == ApproximationMode.SAMPLED.value else approx),
        simulation_seed=seed,
        score_input_version=score_input_version,
        estimated_business_impact=estimated_business_impact,
        total_assets=total_assets,
        metadata={"scale_factor": scale},
    )
