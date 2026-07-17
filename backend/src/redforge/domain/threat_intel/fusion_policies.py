"""Fusion policies — M22 Phase 4.

`FusionConflictPolicy` and `IndicatorTTLPolicy` are pure domain
policies: no I/O, no ORM, no application imports. Default source
weights are documented here so a new platform with no admin override
never has undefined fusion behavior (Hardening Review P1).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from redforge.domain.threat_intel.fusion_value_objects import (
    AggregatedRisk,
    AggregatedRiskState,
    FusionConfidence,
    FusionConflictReason,
    FusionWeight,
    RiskSourceBreakdown,
    SourceAttribution,
    fusion_confidence_rank,
    max_fusion_confidence,
)
from redforge.domain.threat_intel.reference_data_value_objects import ReferenceDataSource

if TYPE_CHECKING:
    from collections.abc import Sequence

# Documented default weight table (Hardening Review P1).
# Higher weight = higher trust when sources conflict.
# Aggressive / noisier feeds sit below curated catalog feeds.
DEFAULT_FUSION_WEIGHTS: dict[str, float] = {
    ReferenceDataSource.MITRE_ATTACK.value: 1.00,
    ReferenceDataSource.CISA_KEV.value: 0.95,
    ReferenceDataSource.NVD_CVE.value: 0.90,
    ReferenceDataSource.EPSS_FIRST.value: 0.80,
    ReferenceDataSource.STIX_TAXII_FEED.value: 0.70,
}

_DEFAULT_WEIGHT_FALLBACK = 0.50

# TTL by fused indicator type (hours). Technique/tactic catalog rows are
# long-lived; STIX-derived software/campaign/group stubs refresh sooner.
_DEFAULT_TTL_HOURS: dict[str, int] = {
    "technique": 24 * 30,
    "tactic": 24 * 30,
    "vulnerability": 24 * 7,
    "software": 24 * 14,
    "campaign": 24 * 14,
    "group": 24 * 14,
    "mitigation": 24 * 30,
}

# Minimum distinct source systems before fusion confidence may exceed MEDIUM
# for GROUP (actor) attribution-shaped indicators.
_ACTOR_CORROBORATION_FLOOR = 2


class FusionConflictPolicy:
    """Resolve multi-source attributions into one `AggregatedRisk`.

    Rules (architecture freeze + hardening):
    1. No attributions → explicit `NO_EVIDENCE` sentinel (never stale reuse).
    2. Higher weight wins on conflict; equal weight → recency wins.
    3. Conflict is recorded in the breakdown (`prevailed` + reason).
    4. GROUP indicators require ≥2 corroborating sources before confidence
       may exceed MEDIUM.
    """

    def __init__(self, weights: Sequence[FusionWeight] | None = None) -> None:
        table = dict(DEFAULT_FUSION_WEIGHTS)
        if weights:
            for item in weights:
                table[item.source_system] = item.weight
        self._weights = table

    def weight_for(self, source_system: str) -> float:
        return self._weights.get(source_system, _DEFAULT_WEIGHT_FALLBACK)

    def aggregate(
        self,
        attributions: Sequence[SourceAttribution],
        *,
        indicator_type: str,
        now: datetime | None = None,
    ) -> AggregatedRisk:
        computed_at = now or datetime.now(UTC)
        if not attributions:
            return AggregatedRisk(
                state=AggregatedRiskState.NO_EVIDENCE,
                confidence=None,
                sources=(),
                computed_at=computed_at,
            )

        ranked = sorted(
            attributions,
            key=lambda a: (
                self.weight_for(a.source_system),
                a.observed_at,
            ),
            reverse=True,
        )
        winner = ranked[0]
        winner_weight = self.weight_for(winner.source_system)

        breakdown: list[RiskSourceBreakdown] = []
        saw_conflict = False
        for attr in ranked:
            weight = self.weight_for(attr.source_system)
            prevailed = attr is winner
            reason: FusionConflictReason | None = None
            if not prevailed:
                saw_conflict = True
                if weight < winner_weight:
                    reason = FusionConflictReason.WEIGHT_PREVAILED
                else:
                    reason = FusionConflictReason.RECENCY_TIEBREAK
            breakdown.append(
                RiskSourceBreakdown(
                    source_system=attr.source_system,
                    weight_applied=weight,
                    confidence=attr.confidence,
                    observed_at=attr.observed_at,
                    prevailed=prevailed,
                    conflict_reason=reason,
                )
            )

        confidence = winner.confidence
        # Lift confidence when multiple distinct sources corroborate.
        distinct_sources = {a.source_system for a in attributions}
        if len(distinct_sources) >= 3:
            confidence = max_fusion_confidence(confidence, FusionConfidence.HIGH)
        elif len(distinct_sources) >= 2:
            confidence = max_fusion_confidence(confidence, FusionConfidence.MEDIUM)

        if (
            indicator_type == "group"
            and len(distinct_sources) < _ACTOR_CORROBORATION_FLOOR
            and fusion_confidence_rank(confidence)
            > fusion_confidence_rank(FusionConfidence.MEDIUM)
        ):
            confidence = FusionConfidence.MEDIUM
            saw_conflict = True
            # Annotate winner row with corroboration floor reason.
            breakdown[0] = RiskSourceBreakdown(
                source_system=breakdown[0].source_system,
                weight_applied=breakdown[0].weight_applied,
                confidence=breakdown[0].confidence,
                observed_at=breakdown[0].observed_at,
                prevailed=True,
                conflict_reason=FusionConflictReason.CORROBORATION_INSUFFICIENT,
            )

        return AggregatedRisk(
            state=(
                AggregatedRiskState.CONFLICT
                if saw_conflict
                else AggregatedRiskState.COMPUTED
            ),
            confidence=confidence,
            sources=tuple(breakdown),
            computed_at=computed_at,
            winner_source_system=winner.source_system,
        )


class IndicatorTTLPolicy:
    """Expiry rules per fused indicator type."""

    def __init__(self, ttl_hours: dict[str, int] | None = None) -> None:
        self._ttl_hours = dict(_DEFAULT_TTL_HOURS)
        if ttl_hours:
            self._ttl_hours.update(ttl_hours)

    def valid_until(
        self, indicator_type: str, *, valid_from: datetime
    ) -> datetime | None:
        hours = self._ttl_hours.get(indicator_type)
        if hours is None:
            return None
        return valid_from + timedelta(hours=hours)

    def is_expired(self, indicator_type: str, *, valid_from: datetime, now: datetime) -> bool:
        until = self.valid_until(indicator_type, valid_from=valid_from)
        if until is None:
            return False
        return now > until
