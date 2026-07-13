"""Computes SecurityPostureScore from a list of ValidationSnapshots.

SecurityPostureCalculator is a stateless domain service. It aggregates
metrics from all snapshots in the given window and calls TrendAnalyzer
to determine the overall direction.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from redforge.application.posture.trend_analyzer import TrendAnalyzer
from redforge.domain.posture.value_objects import (
    PostureLevel,
    SecurityPostureScore,
    TrendDirection,
    TrendPolicy,
    ValidationWindow,
)

if TYPE_CHECKING:
    from redforge.domain.posture.entity import ValidationSnapshot


class SecurityPostureCalculator:
    """Stateless service: aggregate snapshots into SecurityPostureScore.

    Usage:
        calc = SecurityPostureCalculator()
        score = calc.calculate(snapshots, window)
    """

    def __init__(self, policy: TrendPolicy | None = None) -> None:
        self._trend_analyzer = TrendAnalyzer(policy)

    def calculate(
        self,
        snapshots: list[ValidationSnapshot],
        window: ValidationWindow,
    ) -> SecurityPostureScore:
        if not snapshots:
            return self._empty_score()

        rates = [s.vulnerability_rate for s in snapshots]
        mean_rate = sum(rates) / len(rates)

        total_findings = sum(s.metrics.finding_count for s in snapshots)
        target_ids = {s.target_id for s in snapshots}
        targets_assessed = len(target_ids)

        critical_targets = sum(
            1
            for tid in target_ids
            if self._target_is_critical(tid, snapshots)
        )

        trend = TrendDirection.NEW
        with contextlib.suppress(Exception):
            computed = self._trend_analyzer.compute(snapshots, window)
            trend = computed.direction

        return SecurityPostureScore(
            mean_vulnerability_rate=mean_rate,
            level=PostureLevel.from_vulnerability_rate(mean_rate),
            targets_assessed=targets_assessed,
            total_findings=total_findings,
            critical_targets=critical_targets,
            trend=trend,
            snapshot_count=len(snapshots),
        )

    def _target_is_critical(
        self,
        target_id: str,
        snapshots: list[ValidationSnapshot],
    ) -> bool:
        target_snapshots = [s for s in snapshots if s.target_id == target_id]
        if not target_snapshots:
            return False
        latest = max(target_snapshots, key=lambda s: s.created_at)
        level = PostureLevel.from_vulnerability_rate(latest.vulnerability_rate)
        return level == PostureLevel.CRITICAL

    def _empty_score(self) -> SecurityPostureScore:
        return SecurityPostureScore(
            mean_vulnerability_rate=0.0,
            level=PostureLevel.EXCELLENT,
            targets_assessed=0,
            total_findings=0,
            critical_targets=0,
            trend=TrendDirection.NEW,
            snapshot_count=0,
        )
