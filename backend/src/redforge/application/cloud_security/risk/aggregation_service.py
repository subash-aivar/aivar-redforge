"""Aggregate risk scores for org/account summaries."""

from __future__ import annotations

from collections import Counter

from redforge.application.cloud_security.risk.dtos import RiskSummaryDTO
from redforge.domain.cloud_security.risk.score import CloudRiskScore


class RiskAggregationService:
    def summarize(
        self, *, organization_id: str, scores: list[CloudRiskScore]
    ) -> RiskSummaryDTO:
        if not scores:
            return RiskSummaryDTO(
                organization_id=organization_id,
                total_scores=0,
                average_score=0.0,
                critical_count=0,
                high_count=0,
            )
        total = sum(s.overall_score for s in scores)
        by_state = Counter(s.state.value for s in scores)
        by_trend = Counter(s.trend.value for s in scores)
        critical = sum(1 for s in scores if s.overall_score >= 9.0)
        high = sum(1 for s in scores if 7.0 <= s.overall_score < 9.0)
        return RiskSummaryDTO(
            organization_id=organization_id,
            total_scores=len(scores),
            average_score=round(total / len(scores), 4),
            critical_count=critical,
            high_count=high,
            by_state=dict(by_state),
            by_trend=dict(by_trend),
        )

    def top_n(
        self, scores: list[CloudRiskScore], *, n: int = 10
    ) -> list[CloudRiskScore]:
        ordered = sorted(scores, key=lambda s: s.overall_score, reverse=True)
        return ordered[: max(0, n)]
