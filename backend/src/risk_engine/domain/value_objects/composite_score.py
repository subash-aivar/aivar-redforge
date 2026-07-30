"""CompositeRiskScore — the output of `RiskCompositionService`: a
single normalized score plus which `RiskWeightProfile` produced it,
referenced by name/version only (never embedding the whole profile, to
keep this value object small and avoid duplicating weight data)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from risk_engine.domain.exceptions.domain_exceptions import InvalidRiskWeightProfileError
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore


@dataclass(frozen=True, slots=True)
class CompositeRiskScore:
    value: NormalizedRiskScore
    weight_profile_id: str
    computed_at: datetime

    def __post_init__(self) -> None:
        if not self.weight_profile_id.strip():
            raise InvalidRiskWeightProfileError("weight_profile_id must be a non-empty string")
