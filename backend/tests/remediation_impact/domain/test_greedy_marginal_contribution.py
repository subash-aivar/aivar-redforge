from __future__ import annotations

from datetime import UTC, datetime

import pytest

from remediation_impact.domain.exceptions.domain_exceptions import EmptyCandidateSet
from remediation_impact.domain.services.greedy_marginal_contribution import (
    derive_simulation_seed,
    portfolio_weighted_sample,
    run_greedy_marginal_contribution,
)
from remediation_impact.domain.value_objects.simulation_vos import RemediationCandidate


def _candidates() -> list[RemediationCandidate]:
    return [
        RemediationCandidate("r1", ("a1",), (), 2.0),
        RemediationCandidate("r2", ("a2",), (), 1.5),
        RemediationCandidate("r3", ("a1", "a2"), (), 0.5),
    ]


def test_exact_mode_deterministic() -> None:
    at = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    scores = {"a1": 5.0, "a2": 4.0, "a3": 1.0}
    r1 = run_greedy_marginal_contribution(
        candidates=_candidates(),
        current_exposure_scores=scores,
        plan_budget=2,
        top_k=10,
        sample_size=None,
        plan_generated_at=at,
        score_input_version=3,
    )
    r2 = run_greedy_marginal_contribution(
        candidates=_candidates(),
        current_exposure_scores=scores,
        plan_budget=2,
        top_k=10,
        sample_size=None,
        plan_generated_at=at,
        score_input_version=3,
    )
    assert r1.simulation_seed == r2.simulation_seed == derive_simulation_seed(at)
    assert r1.plan_steps == r2.plan_steps
    assert r1.projected_exposure_reduction == r2.projected_exposure_reduction
    assert r1.approximation_mode == "Exact"
    assert r1.estimated_business_impact > 0


def test_sampled_mode_deterministic() -> None:
    at = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    scores = {f"a{i}": float(i % 10) for i in range(50)}
    r1 = run_greedy_marginal_contribution(
        candidates=_candidates(),
        current_exposure_scores=scores,
        plan_budget=2,
        top_k=10,
        sample_size=20,
        plan_generated_at=at,
        score_input_version=1,
    )
    r2 = run_greedy_marginal_contribution(
        candidates=_candidates(),
        current_exposure_scores=scores,
        plan_budget=2,
        top_k=10,
        sample_size=20,
        plan_generated_at=at,
        score_input_version=1,
    )
    assert "Sampled" in r1.approximation_mode
    assert r1.plan_steps == r2.plan_steps
    assert r1.simulation_seed == r2.simulation_seed


def test_portfolio_sample_size() -> None:
    scores = {f"a{i}": float(100 - i) for i in range(100)}
    sampled = portfolio_weighted_sample(scores, 20, seed=42)
    assert len(sampled) == 20
    assert portfolio_weighted_sample(scores, 20, seed=42) == sampled


def test_empty_candidates_rejected() -> None:
    with pytest.raises(EmptyCandidateSet):
        run_greedy_marginal_contribution(
            candidates=[],
            current_exposure_scores={"a1": 1.0},
            plan_budget=1,
            plan_generated_at=datetime.now(UTC),
            score_input_version=1,
        )
