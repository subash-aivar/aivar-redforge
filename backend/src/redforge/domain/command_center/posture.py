"""Deterministic, versioned, fully-explainable posture score — M18.

This is intentionally NOT a probabilistic risk model, an ML score, or a
CVSS aggregate. It is a pure, deterministic weighted deduction over real
counts of currently-ACTIVE security conditions (grouped by severity) and
currently-ACTIVE security correlations. The same inputs always produce
the same output, the formula version is published alongside every
result, and the full contributing breakdown is returned so the UI can
show exactly why the score is what it is.

Score = clamp(0, 100, 100 - sum(count_severity x weight_severity)
                            - active_correlations x CORRELATION_WEIGHT)

There is NO time-series/trend component — the platform has no
time-bucketed posture history table, so no trend line is ever fabricated.
"""

from __future__ import annotations

from dataclasses import dataclass

from redforge.domain.command_center.value_objects import PostureBand

POSTURE_SCORE_FORMULA_VERSION = "1.0.0"

# Deduction weight per ACTIVE condition, by normalized severity. An
# unrecognized severity string is counted under "unknown" at the medium
# weight (conservative: an un-triaged severity is not treated as benign).
_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 15,
    "high": 8,
    "medium": 3,
    "low": 1,
    "info": 0,
    "unknown": 3,
}

# A correlation is a higher-order finding (multiple conditions relating
# on one asset / across assets); it deducts more than a single condition.
CORRELATION_WEIGHT = 10

# Band thresholds (inclusive lower bounds).
_BAND_THRESHOLDS: list[tuple[int, PostureBand]] = [
    (90, PostureBand.STRONG),
    (70, PostureBand.MODERATE),
    (40, PostureBand.AT_RISK),
    (0, PostureBand.CRITICAL),
]


@dataclass(frozen=True, slots=True)
class PostureContribution:
    """One line of the deduction breakdown — what deducted, how much."""

    factor: str
    count: int
    weight: int
    deduction: int


@dataclass(frozen=True, slots=True)
class PostureScore:
    score: int
    band: PostureBand
    formula_version: str
    total_deduction: int
    contributions: list[PostureContribution]
    active_condition_count: int
    active_correlation_count: int


def _normalize_severity(raw: str) -> str:
    s = (raw or "").strip().lower()
    return s if s in _SEVERITY_WEIGHTS else "unknown"


def compute_posture_score(
    active_conditions_by_severity: dict[str, int],
    active_correlation_count: int,
) -> PostureScore:
    """Pure function. `active_conditions_by_severity` maps a (possibly
    un-normalized) severity string to a count of ACTIVE conditions with
    that severity; `active_correlation_count` is the number of ACTIVE
    correlations. Both must already be scoped to one organization."""
    # Fold raw severities into the normalized weight buckets.
    folded: dict[str, int] = {}
    for raw, count in active_conditions_by_severity.items():
        if count <= 0:
            continue
        folded[_normalize_severity(raw)] = folded.get(_normalize_severity(raw), 0) + count

    contributions: list[PostureContribution] = []
    total_deduction = 0
    active_condition_count = 0
    # Deterministic ordering by descending weight then name.
    for sev in sorted(folded, key=lambda s: (-_SEVERITY_WEIGHTS[s], s)):
        count = folded[sev]
        active_condition_count += count
        weight = _SEVERITY_WEIGHTS[sev]
        deduction = count * weight
        if deduction:
            contributions.append(
                PostureContribution(
                    factor=f"active_conditions:{sev}", count=count,
                    weight=weight, deduction=deduction,
                )
            )
            total_deduction += deduction

    if active_correlation_count > 0:
        deduction = active_correlation_count * CORRELATION_WEIGHT
        contributions.append(
            PostureContribution(
                factor="active_correlations", count=active_correlation_count,
                weight=CORRELATION_WEIGHT, deduction=deduction,
            )
        )
        total_deduction += deduction

    score = max(0, min(100, 100 - total_deduction))

    band = PostureBand.CRITICAL
    for threshold, candidate in _BAND_THRESHOLDS:
        if score >= threshold:
            band = candidate
            break

    return PostureScore(
        score=score,
        band=band,
        formula_version=POSTURE_SCORE_FORMULA_VERSION,
        total_deduction=total_deduction,
        contributions=contributions,
        active_condition_count=active_condition_count,
        active_correlation_count=active_correlation_count,
    )
