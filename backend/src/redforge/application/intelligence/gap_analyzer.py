"""Security gap detection — identifies structural gaps beyond coverage rate.

GapAnalyzer is stateless. It looks for:
  - Targets with no recent validation (temporal gap)
  - Providers not validated at all (provider gap)
  - Coverage gaps exceeding threshold (attack gap summary)
  - Drift events with no follow-up validation (drift gap)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.domain.intelligence.value_objects import (
    AttackCoverageGap,
    GapType,
    RecommendationPriority,
    SecurityGap,
)

if TYPE_CHECKING:
    from redforge.application.intelligence.contracts import IntelligenceContext

# Targets not validated in this many days get a TEMPORAL_COVERAGE gap
_STALE_VALIDATION_THRESHOLD_DAYS = 30


class GapAnalyzer:
    """Stateless service: identify structural security gaps.

    Usage:
        analyzer = GapAnalyzer(stale_days=30)
        gaps = analyzer.analyze(context, coverage_gaps)
    """

    def __init__(self, stale_days: int = _STALE_VALIDATION_THRESHOLD_DAYS) -> None:
        self._stale_days = stale_days

    def analyze(
        self,
        context: IntelligenceContext,
        coverage_gaps: list[AttackCoverageGap],
    ) -> list[SecurityGap]:
        gaps: list[SecurityGap] = []
        gaps.extend(self._temporal_gaps(context))
        gaps.extend(self._provider_gaps(context))
        gaps.extend(self._attack_coverage_summary_gaps(coverage_gaps))
        gaps.extend(self._drift_without_followup_gaps(context))
        return gaps

    def _temporal_gaps(self, context: IntelligenceContext) -> list[SecurityGap]:
        """Targets with no snapshot in the stale threshold window."""
        stale: list[str] = []
        for target_id in context.target_ids:
            target_snaps = [s for s in context.snapshots if s.target_id == target_id]
            if not target_snaps:
                stale.append(target_id)
                continue
            most_recent_iso = max(
                (s.created_at_iso for s in target_snaps if s.created_at_iso),
                default="",
            )
            if most_recent_iso:
                days = _days_since_iso(most_recent_iso)
                if days > self._stale_days:
                    stale.append(target_id)

        if not stale:
            return []

        severity = (
            RecommendationPriority.HIGH if len(stale) > len(context.target_ids) // 2
            else RecommendationPriority.MEDIUM
        )
        return [SecurityGap(
            gap_type=GapType.TEMPORAL_COVERAGE,
            description=(
                f"{len(stale)} target(s) have not been validated in the last "
                f"{self._stale_days} days: {', '.join(stale[:5])}"
                + (" and more" if len(stale) > 5 else "")
            ),
            affected_targets=tuple(stale),
            severity=severity,
            metadata={"stale_threshold_days": self._stale_days},
        )]

    def _provider_gaps(self, context: IntelligenceContext) -> list[SecurityGap]:
        """Providers that appear in snapshots but whose targets share no coverage."""
        # We identify if some providers are absent from coverage entirely
        providers_validated: set[str] = {
            s.provider for s in context.snapshots if s.provider
        }
        # If fewer than 2 unique providers are validated across all snapshots, flag it
        if len(providers_validated) < 2 and len(context.snapshots) >= 3:
            return [SecurityGap(
                gap_type=GapType.PROVIDER_COVERAGE,
                description=(
                    f"Validation history covers only {len(providers_validated)} "
                    f"provider(s). Multi-provider validation is recommended to detect "
                    f"provider-specific vulnerabilities."
                ),
                affected_targets=context.target_ids,
                severity=RecommendationPriority.MEDIUM,
                metadata={"validated_providers": list(providers_validated)},
            )]
        return []

    def _attack_coverage_summary_gaps(
        self,
        coverage_gaps: list[AttackCoverageGap],
    ) -> list[SecurityGap]:
        """Targets with critical-severity coverage gaps."""
        critical_targets = [
            g.target_id for g in coverage_gaps
            if g.gap_severity == RecommendationPriority.CRITICAL
        ]
        if not critical_targets:
            return []
        return [SecurityGap(
            gap_type=GapType.ATTACK_COVERAGE,
            description=(
                f"{len(critical_targets)} target(s) have tested less than 25% "
                f"of known attack categories. Immediate coverage expansion required."
            ),
            affected_targets=tuple(critical_targets),
            severity=RecommendationPriority.HIGH,
        )]

    def _drift_without_followup_gaps(
        self,
        context: IntelligenceContext,
    ) -> list[SecurityGap]:
        """Drift events where no validation occurred after the drift."""
        if not context.drift_events:
            return []

        # Find targets with significant drift but no subsequent snapshot
        targets_with_drift_no_followup: list[str] = []
        for drift in context.drift_events:
            if not drift.is_significant:
                continue
            target_id = drift.target_id
            drift_snap_id = drift.target_snapshot_id
            # Check if any snapshot exists after the drifted snapshot
            target_snaps = [s for s in context.snapshots if s.target_id == target_id]
            later_snaps = [
                s for s in target_snaps
                if s.snapshot_id != drift_snap_id
                and s.snapshot_id > drift_snap_id  # ULID is lexicographically sortable
            ]
            if not later_snaps:
                targets_with_drift_no_followup.append(target_id)

        if not targets_with_drift_no_followup:
            return []

        return [SecurityGap(
            gap_type=GapType.TARGET_COVERAGE,
            description=(
                f"{len(targets_with_drift_no_followup)} target(s) have significant "
                f"configuration drift with no follow-up validation. "
                f"Drift may have introduced new vulnerabilities."
            ),
            affected_targets=tuple(targets_with_drift_no_followup),
            severity=RecommendationPriority.HIGH,
        )]


def _days_since_iso(iso_str: str) -> int:
    import contextlib

    with contextlib.suppress(Exception):
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - dt).days)
    return 0
