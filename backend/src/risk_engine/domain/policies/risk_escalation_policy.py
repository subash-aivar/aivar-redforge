"""RiskEscalationPolicy — decides whether an `EnterpriseRiskProfile`
should be escalated given a critical-severity threshold.

Precedence rule (see `RiskAcceptanceExpiryPolicy` for the paired
half of this documented tie-break): if both `RiskEscalationPolicy.
should_escalate` and `RiskAcceptanceExpiryPolicy.is_expired` would fire
for the same profile in the same evaluation, escalation wins. A
currently-critical score must never stay silently accepted — expiry
alone is not grounds to suppress an active escalation signal."""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.domain.value_objects.enums import RiskProfileStatus

if TYPE_CHECKING:
    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
    from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore

_NOT_ESCALATABLE_STATUSES = {RiskProfileStatus.OPEN, RiskProfileStatus.CLOSED}


class RiskEscalationPolicy:
    @staticmethod
    def should_escalate(
        profile: EnterpriseRiskProfile, critical_threshold: NormalizedRiskScore
    ) -> bool:
        if profile.status in _NOT_ESCALATABLE_STATUSES:
            return False
        if profile.composite_score is None:
            return False
        return profile.composite_score.value.value >= critical_threshold.value
