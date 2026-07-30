"""Simple predicate specifications for risk_engine (M48B).

This codebase has no pre-existing Specification-pattern precedent
elsewhere in `src/` (a repo-wide grep for `Specification` returned no
hits at the time this was written), so these are implemented as
lightweight frozen dataclasses with an `is_satisfied_by(...)` method —
idiomatically consistent with the rest of this domain layer's frozen
value-object style rather than importing an unfamiliar pattern."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from risk_engine.domain.services.risk_correlation_service import RiskCorrelationService

if TYPE_CHECKING:
    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
    from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
    from risk_engine.domain.value_objects.risk_signal import RiskSignalReference


@dataclass(frozen=True, slots=True)
class IsCriticalRiskSpecification:
    threshold: NormalizedRiskScore

    def is_satisfied_by(self, profile: EnterpriseRiskProfile) -> bool:
        if profile.composite_score is None:
            return False
        return profile.composite_score.value.value >= self.threshold.value


@dataclass(frozen=True, slots=True)
class IsStaleRiskProfileSpecification:
    max_age: timedelta

    def is_satisfied_by(self, profile: EnterpriseRiskProfile, now: datetime) -> bool:
        return (now - profile.updated_at) > self.max_age


@dataclass(frozen=True, slots=True)
class IsCorrelatableSignalSpecification:
    """Consistent with `RiskCorrelationService.are_correlatable` — this
    specification delegates to it rather than re-implementing the
    subject-reference-keyed correlation rule."""

    window: timedelta

    def is_satisfied_by(self, a: RiskSignalReference, b: RiskSignalReference) -> bool:
        return RiskCorrelationService.are_correlatable(a, b, window=self.window)
