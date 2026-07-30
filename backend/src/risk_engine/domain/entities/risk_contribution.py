"""RiskContribution — one dimension's contribution to an
`EnterpriseRiskProfile`'s composite score at a point in time. Owned
exclusively within `EnterpriseRiskProfile`; never referenced by id from
outside the aggregate. Modeled as a frozen dataclass — nothing about a
contribution mutates after it is recorded; a new contribution replaces
it on the next recompute."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from risk_engine.domain.value_objects.enums import RiskDimension
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference


@dataclass(frozen=True, slots=True)
class RiskContribution:
    dimension: RiskDimension
    normalized_score: NormalizedRiskScore
    source_signal: RiskSignalReference
    computed_at: datetime
