"""RiskAcceptanceExpiryPolicy — decides whether an accepted risk's
expiry window has elapsed.

Precedence rule (documented in both policies to keep it discoverable
from either side): if this policy's `is_expired` and
`RiskEscalationPolicy.should_escalate` would both fire for the same
profile in the same evaluation, escalation wins — a currently-critical
score should never stay silently accepted just because its acceptance
window also happens to have expired. Callers evaluating both policies
must check escalation first and short-circuit on a positive result."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile


class RiskAcceptanceExpiryPolicy:
    @staticmethod
    def is_expired(
        profile: EnterpriseRiskProfile,
        accepted_at: datetime,
        expires_at: datetime,
        now: datetime,
    ) -> bool:
        del profile, accepted_at  # unused; signature kept for future acceptance-context checks
        return now >= expires_at
