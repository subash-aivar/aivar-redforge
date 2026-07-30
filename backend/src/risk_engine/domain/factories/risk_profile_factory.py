"""RiskProfileFactory — the only supported way to construct an
`EnterpriseRiskProfile`. Enforces the "must own at least one signal at
creation" invariant here rather than in the aggregate's `__init__`,
per the frozen architecture spec's factory design.

Judgment call: `composite_score` is left `None` at creation rather
than deriving a degenerate one-term weighted average from the single
initial contribution. A meaningful composite score requires a
`RiskWeightProfile` (see `RiskCompositionService.compose`), which the
factory does not require callers to supply just to create a profile —
the first real composite score is produced by an explicit
`recompute_score` call once a weight profile is available."""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile

if TYPE_CHECKING:
    from datetime import datetime

    from risk_engine.domain.entities.risk_contribution import RiskContribution
    from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId


class RiskProfileFactory:
    @staticmethod
    def create(
        tenant_id: TenantId,
        subject_reference: str,
        initial_contribution: RiskContribution,
        now: datetime,
        profile_id: RiskProfileId | None = None,
    ) -> EnterpriseRiskProfile:
        from risk_engine.domain.value_objects.identifiers import RiskProfileId as _RiskProfileId

        resolved_id = profile_id or _RiskProfileId.generate()
        return EnterpriseRiskProfile._create(
            profile_id=resolved_id,
            tenant_id=tenant_id,
            subject_reference=subject_reference,
            now=now,
            contributions=(initial_contribution,),
        )
