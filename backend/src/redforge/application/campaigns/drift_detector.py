"""Campaign drift detector.

Compares the current campaign's per-target results against a baseline
campaign to produce a DriftSummary. The detector is a pure function
object — it takes data in and returns a value object; it has no side
effects and no I/O of its own (the caller fetches baseline data via
BaselineCampaignPort before invoking this).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.campaigns.value_objects import DriftSummary, TargetResult
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


class DriftDetector:
    """Produces a DriftSummary by comparing current vs baseline results.

    Usage:
        detector = DriftDetector()
        summary = detector.detect(
            baseline_campaign_id=...,
            baseline_findings={target_id: count, ...},
            baseline_vuln_rates={target_id: rate, ...},
            current_results=[...],
        )
    """

    def detect(
        self,
        baseline_campaign_id: EntityId,
        baseline_findings: dict[str, int],
        baseline_vuln_rates: dict[str, float],
        current_results: list[TargetResult],
        baseline_completed_at: datetime | None = None,
    ) -> DriftSummary:
        """Compute drift between baseline campaign and current results.

        new_findings_count: targets that now have MORE findings than baseline.
        resolved_findings_count: targets that now have FEWER findings.
        vulnerability_rate_delta: mean(current rates) - mean(baseline rates).
        """
        completed_at = baseline_completed_at or utc_now()

        new_findings = 0
        resolved_findings = 0
        total_rate_delta = 0.0
        compared = 0

        for result in current_results:
            tid = str(result.target_id)
            if not result.succeeded:
                continue

            baseline_count = baseline_findings.get(tid, 0)
            current_count = result.findings_count

            if current_count > baseline_count:
                new_findings += current_count - baseline_count
            elif current_count < baseline_count:
                resolved_findings += baseline_count - current_count

            baseline_rate = baseline_vuln_rates.get(tid, 0.0)
            total_rate_delta += result.vulnerability_rate - baseline_rate
            compared += 1

        mean_rate_delta = total_rate_delta / compared if compared > 0 else 0.0

        return DriftSummary(
            baseline_campaign_id=baseline_campaign_id,
            baseline_completed_at=completed_at,
            new_findings_count=new_findings,
            resolved_findings_count=resolved_findings,
            vulnerability_rate_delta=round(mean_rate_delta, 4),
        )
