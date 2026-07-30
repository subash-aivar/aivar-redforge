"""RiskCompositionService — composes a `CompositeRiskScore` from a set
of `RiskContribution`s and a `RiskWeightProfile`. Stateless, pure, no
I/O. Implements Step 6 of the frozen architecture spec's formula:
weighted average over only the dimensions actually present:

    sum(dimension_weight x normalized_dimension_score) / sum(weights of populated dimensions)

Dimensions with a positive weight in the profile but no contribution
are simply excluded from both the numerator and denominator — a
missing signal never silently counts as zero risk, and never inflates
the denominator with an unused weight."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from risk_engine.domain.exceptions.domain_exceptions import EmptyContributionsError
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore

if TYPE_CHECKING:
    from collections.abc import Sequence

    from risk_engine.domain.entities.risk_contribution import RiskContribution
    from risk_engine.domain.value_objects.weight_profile import RiskWeightProfile


class RiskCompositionService:
    @staticmethod
    def compose(
        contributions: Sequence[RiskContribution],
        weight_profile: RiskWeightProfile,
    ) -> CompositeRiskScore:
        if not contributions:
            raise EmptyContributionsError()

        weighted_sum = 0.0
        weight_sum = 0.0
        for contribution in contributions:
            weight = weight_profile.weight_for(contribution.dimension)
            if weight <= 0.0:
                continue
            weighted_sum += weight * contribution.normalized_score.value
            weight_sum += weight

        value = (weighted_sum / weight_sum) if weight_sum > 0.0 else 0.0
        return CompositeRiskScore(
            value=NormalizedRiskScore(value),
            weight_profile_id=f"{weight_profile.profile_name}:v{weight_profile.version}",
            computed_at=datetime.now(UTC),
        )
