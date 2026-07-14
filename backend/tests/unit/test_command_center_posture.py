"""Fast, no-DB unit proof of the deterministic M18 posture score.

`compute_posture_score` is a pure function (redforge.domain.command_
center.posture); every assertion here is a hand-computed expectation
against the documented weight table:

    critical=15, high=8, medium=3, low=1, info=0, unknown(any other)=3,
    correlation_weight=10, score = clamp(0, 100, 100 - total_deduction),
    bands: >=90 strong, >=70 moderate, >=40 at_risk, else critical.

No weakened assertions: each score/band/breakdown is derived by hand.
"""

from __future__ import annotations

import pytest

from redforge.domain.command_center.posture import (
    POSTURE_SCORE_FORMULA_VERSION,
    compute_posture_score,
)
from redforge.domain.command_center.value_objects import PostureBand


def test_empty_inputs_are_a_perfect_strong_score() -> None:
    result = compute_posture_score({}, 0)
    assert result.score == 100
    assert result.band is PostureBand.STRONG
    assert result.total_deduction == 0
    assert result.contributions == []
    assert result.active_condition_count == 0
    assert result.active_correlation_count == 0
    assert result.formula_version == "1.0.0"
    assert result.formula_version == POSTURE_SCORE_FORMULA_VERSION


def test_single_critical_condition_deducts_fifteen() -> None:
    result = compute_posture_score({"critical": 1}, 0)
    assert result.total_deduction == 15
    assert result.score == 85
    assert result.band is PostureBand.MODERATE  # 85 >= 70
    assert result.active_condition_count == 1
    assert len(result.contributions) == 1
    c = result.contributions[0]
    assert (c.factor, c.count, c.weight, c.deduction) == ("active_conditions:critical", 1, 15, 15)


def test_mixed_severities_and_correlations_exact_breakdown() -> None:
    # critical 2*15=30, high 3*8=24, medium 4*3=12, low 5*1=5, info 10*0=0,
    # correlations 2*10=20 => total 91 => score 9 => critical band.
    result = compute_posture_score(
        {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 10}, 2,
    )
    assert result.total_deduction == 91
    assert result.score == 9
    assert result.band is PostureBand.CRITICAL
    # info conditions still count toward the total active count (weight 0).
    assert result.active_condition_count == 24
    assert result.active_correlation_count == 2

    by_factor = {c.factor: c for c in result.contributions}
    # info deducts nothing => no contribution line for it.
    assert "active_conditions:info" not in by_factor
    assert by_factor["active_conditions:critical"].deduction == 30
    assert by_factor["active_conditions:high"].deduction == 24
    assert by_factor["active_conditions:medium"].deduction == 12
    assert by_factor["active_conditions:low"].deduction == 5
    assert by_factor["active_correlations"].count == 2
    assert by_factor["active_correlations"].weight == 10
    assert by_factor["active_correlations"].deduction == 20


def test_contribution_ordering_is_descending_weight_then_name() -> None:
    # medium and unknown share weight 3 => tie broken by name ("medium" < "unknown").
    result = compute_posture_score(
        {"low": 1, "critical": 1, "medium": 1, "weird": 1, "high": 1}, 1,
    )
    factors = [c.factor for c in result.contributions]
    assert factors == [
        "active_conditions:critical",   # weight 15
        "active_conditions:high",       # weight 8
        "active_conditions:medium",     # weight 3, name medium
        "active_conditions:unknown",    # weight 3, name unknown
        "active_conditions:low",        # weight 1
        "active_correlations",          # correlations always appended last
    ]


def test_unrecognized_severity_folds_to_unknown_at_medium_weight() -> None:
    result = compute_posture_score({"catastrophic": 4}, 0)
    assert result.total_deduction == 12  # 4 * 3 (unknown weight)
    assert result.score == 88
    assert result.band is PostureBand.MODERATE
    assert len(result.contributions) == 1
    c = result.contributions[0]
    assert (c.factor, c.count, c.weight, c.deduction) == ("active_conditions:unknown", 4, 3, 12)


def test_multiple_raw_severities_fold_into_one_unknown_bucket() -> None:
    # both "weird" and the literal "unknown" normalize to the unknown bucket.
    result = compute_posture_score({"weird": 2, "unknown": 3}, 0)
    assert result.active_condition_count == 5
    unknown = [c for c in result.contributions if c.factor == "active_conditions:unknown"]
    assert len(unknown) == 1
    assert unknown[0].count == 5
    assert unknown[0].deduction == 15


def test_score_clamps_to_zero_never_negative() -> None:
    result = compute_posture_score({"critical": 100}, 0)
    assert result.total_deduction == 1500
    assert result.score == 0  # clamped, not -1400
    assert result.band is PostureBand.CRITICAL
    assert result.active_condition_count == 100


def test_zero_and_negative_counts_are_ignored() -> None:
    result = compute_posture_score({"critical": 0, "high": -3, "medium": 0}, 0)
    assert result.score == 100
    assert result.total_deduction == 0
    assert result.contributions == []
    assert result.active_condition_count == 0


@pytest.mark.parametrize(
    ("severity_counts", "correlations", "expected_score", "expected_band"),
    [
        ({"low": 10}, 0, 90, PostureBand.STRONG),      # exactly 90 -> strong
        ({"critical": 2}, 0, 70, PostureBand.MODERATE),  # exactly 70 -> moderate
        ({"critical": 4}, 0, 40, PostureBand.AT_RISK),   # exactly 40 -> at_risk
        ({"critical": 4, "low": 1}, 0, 39, PostureBand.CRITICAL),  # 39 -> critical
        ({}, 1, 90, PostureBand.STRONG),               # one correlation -> 90
        ({}, 3, 70, PostureBand.MODERATE),             # three correlations -> 70
    ],
)
def test_band_thresholds_are_inclusive_lower_bounds(
    severity_counts: dict[str, int],
    correlations: int,
    expected_score: int,
    expected_band: PostureBand,
) -> None:
    result = compute_posture_score(severity_counts, correlations)
    assert result.score == expected_score
    assert result.band is expected_band


def test_correlation_only_deduction() -> None:
    result = compute_posture_score({}, 4)
    assert result.total_deduction == 40
    assert result.score == 60
    assert result.band is PostureBand.AT_RISK
    assert result.active_condition_count == 0
    assert result.active_correlation_count == 4
    assert len(result.contributions) == 1
    assert result.contributions[0].factor == "active_correlations"
