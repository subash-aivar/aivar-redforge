"""Attack coverage analysis — identifies which categories have and haven't been tested.

CoverageAnalyzer is stateless. Given an IntelligenceContext with snapshot history,
it computes per-target AttackCoverageGap objects showing what's been tested vs. missing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.domain.intelligence.value_objects import AttackCoverageGap

if TYPE_CHECKING:
    from redforge.application.intelligence.contracts import (
        IntelligenceContext,
        SnapshotInput,
    )


class CoverageAnalyzer:
    """Stateless service: compute per-target attack coverage gaps.

    Usage:
        analyzer = CoverageAnalyzer()
        gaps = analyzer.analyze(context)
    """

    def analyze(self, context: IntelligenceContext) -> list[AttackCoverageGap]:
        """Return one AttackCoverageGap per target in the context."""
        if not context.all_known_attack_categories:
            return []

        gaps: list[AttackCoverageGap] = []

        for target_id in context.target_ids:
            target_snaps = [
                s for s in context.snapshots
                if s.target_id == target_id
            ]
            gap = self._analyze_target(
                target_id=target_id,
                organization_id=context.organization_id,
                snapshots=target_snaps,
                all_categories=context.all_known_attack_categories,
            )
            gaps.append(gap)

        return gaps

    def _analyze_target(
        self,
        target_id: str,
        organization_id: str,
        snapshots: list[SnapshotInput],
        all_categories: frozenset[str],
    ) -> AttackCoverageGap:
        tested: set[str] = set()
        latest_created_at_iso: str | None = None

        for snap in snapshots:
            tested.update(snap.executed_categories)
            if snap.created_at_iso and (
                latest_created_at_iso is None or snap.created_at_iso > latest_created_at_iso
            ):
                latest_created_at_iso = snap.created_at_iso

        missing = all_categories - tested
        coverage_rate = len(tested) / len(all_categories) if all_categories else 0.0

        days_since: int | None = None
        if latest_created_at_iso:
            days_since = _days_since_iso(latest_created_at_iso)

        return AttackCoverageGap(
            target_id=target_id,
            organization_id=organization_id,
            tested_categories=frozenset(tested),
            missing_categories=frozenset(missing),
            coverage_rate=coverage_rate,
            days_since_last_validation=days_since,
        )


def _days_since_iso(iso_str: str) -> int:
    """Return days since an ISO 8601 datetime string."""
    import contextlib

    with contextlib.suppress(Exception):
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - dt).days)
    return 0
