"""Deterministic narrative construction for risk and posture context.

NarrativeBuilder is stateless. It produces human-readable
RiskNarrative and PostureNarrative objects from structured data.

This is NOT LLM generation. All strings are composed from
templates and structured inputs. The goal is machine-readable
narrative that can be displayed in UIs or included in reports
without post-processing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.intelligence.value_objects import (
    AttackCoverageGap,
    PostureNarrative,
    RecommendationPriority,
    RiskNarrative,
)

if TYPE_CHECKING:
    from redforge.application.intelligence.contracts import IntelligenceContext
    from redforge.domain.intelligence.entity import Recommendation


class NarrativeBuilder:
    """Stateless service: build human-readable security narratives.

    Usage:
        builder = NarrativeBuilder()
        risk_narrative = builder.build_risk_narrative(context, recommendations)
        posture_narrative = builder.build_posture_narrative(context, coverage_gaps)
    """

    def build_risk_narrative(
        self,
        context: IntelligenceContext,
        recommendations: list[Recommendation],
    ) -> RiskNarrative:
        """Construct a RiskNarrative from risk incidents and recommendations."""
        incidents = context.risk_incidents
        critical_count = sum(1 for i in incidents if i.priority == "critical")
        high_count = sum(1 for i in incidents if i.priority == "high")
        total = len(incidents)

        if total == 0:
            return RiskNarrative(
                summary=(
                    f"No risk incidents detected for organization "
                    f"{context.organization_id!r} in the analysis window."
                ),
                key_risks=(),
                trend_description="Insufficient data to determine risk trend.",
                recommendations_summary="No recommendations generated.",
                critical_incident_count=0,
                high_incident_count=0,
            )

        summary = _compose_risk_summary(
            org_id=context.organization_id,
            total=total,
            critical_count=critical_count,
            high_count=high_count,
            target_count=len(context.target_ids),
            period_days=context.period_days,
        )

        key_risks = tuple(
            f"{i.priority.upper()}: {i.title} (risk score {i.risk_score:.1f}/10)"
            for i in sorted(incidents, key=lambda x: x.risk_score, reverse=True)[:5]
        )

        trend_description = _compose_trend(context)

        critical_recs = [
            r for r in recommendations if r.priority == RecommendationPriority.CRITICAL
        ]
        if critical_recs:
            rec_summary = f"Immediate action required: {critical_recs[0].title}."
        elif recommendations:
            rec_summary = f"Top recommendation: {recommendations[0].title}."
        else:
            rec_summary = "No specific recommendations at this time."

        return RiskNarrative(
            summary=summary,
            key_risks=key_risks,
            trend_description=trend_description,
            recommendations_summary=rec_summary,
            critical_incident_count=critical_count,
            high_incident_count=high_count,
        )

    def build_posture_narrative(
        self,
        context: IntelligenceContext,
        coverage_gaps: list[AttackCoverageGap],
    ) -> PostureNarrative:
        """Construct a PostureNarrative from posture score and coverage gaps."""
        posture = context.posture
        if posture is None:
            return PostureNarrative(
                overall_level="unknown",
                trend_summary="No posture data available for this organization.",
                targets_assessed=0,
                critical_targets=(),
                improvement_areas=(),
                mean_vulnerability_rate=0.0,
            )

        # Identify critical-level targets from snapshots
        target_latest: dict[str, float] = {}
        for snap in context.snapshots:
            existing = target_latest.get(snap.target_id)
            prev = next(
                (s.created_at_iso for s in context.snapshots
                 if s.target_id == snap.target_id and s.snapshot_id != snap.snapshot_id),
                "",
            )
            if existing is None or snap.created_at_iso > prev:
                target_latest[snap.target_id] = snap.vulnerability_rate

        critical_targets = tuple(
            t for t, rate in target_latest.items()
            if rate >= 0.50
        )

        improvement_areas = _compose_improvement_areas(
            posture=posture,
            coverage_gaps=coverage_gaps,
            critical_target_count=len(critical_targets),
        )

        trend_summary = _compose_posture_trend(posture)

        return PostureNarrative(
            overall_level=posture.level,
            trend_summary=trend_summary,
            targets_assessed=posture.targets_assessed,
            critical_targets=critical_targets,
            improvement_areas=improvement_areas,
            mean_vulnerability_rate=posture.mean_vulnerability_rate,
        )


def _compose_risk_summary(
    org_id: str,
    total: int,
    critical_count: int,
    high_count: int,
    target_count: int,
    period_days: int,
) -> str:
    severity_phrase = ""
    if critical_count > 0 and high_count > 0:
        severity_phrase = f"{critical_count} critical and {high_count} high-severity"
    elif critical_count > 0:
        severity_phrase = f"{critical_count} critical-severity"
    elif high_count > 0:
        severity_phrase = f"{high_count} high-severity"
    else:
        severity_phrase = f"{total} medium/low-severity"

    return (
        f"In the last {period_days} days, {total} risk incident(s) were identified "
        f"across {target_count} AI target(s), including {severity_phrase} incident(s). "
        f"Immediate investigation and remediation of critical findings is required."
        if critical_count > 0
        else (
            f"In the last {period_days} days, {total} risk incident(s) were identified "
            f"across {target_count} AI target(s), including {severity_phrase} incident(s)."
        )
    )


def _compose_trend(context: IntelligenceContext) -> str:
    if context.posture:
        trend = context.posture.trend
        level = context.posture.level
        rate = context.posture.mean_vulnerability_rate
        if trend == "improving":
            return (
                f"Security posture is improving (mean vulnerability rate {rate:.1%}). "
                f"Continue current remediation efforts."
            )
        if trend == "degrading":
            return (
                f"Security posture is degrading (mean vulnerability rate {rate:.1%}). "
                f"Escalation and investigation required."
            )
        if trend == "volatile":
            return (
                f"Security posture is volatile (mean vulnerability rate {rate:.1%}). "
                f"Inconsistent remediation pattern detected — systematic approach needed."
            )
        return (
            f"Security posture is stable at {level} level "
            f"(mean vulnerability rate {rate:.1%})."
        )
    return "Insufficient historical data to determine risk trend."


def _compose_posture_trend(posture: object) -> str:
    trend = getattr(posture, "trend", "unknown")
    level = getattr(posture, "level", "unknown")
    rate = getattr(posture, "mean_vulnerability_rate", 0.0)

    r = f"{rate:.1%}"
    _trend_descriptions: dict[str, str] = {
        "improving": f"Overall security posture is improving toward {level} level (mean rate {r}).",
        "degrading": (
            f"Overall security posture is degrading at {level} level (mean rate {r}). "
            f"Immediate attention required."
        ),
        "stable": f"Security posture is stable at {level} level (mean rate {r}).",
        "volatile": (
            f"Security posture is volatile at {level} level (mean rate {r}). "
            f"Inconsistent controls."
        ),
        "new": f"Insufficient history to determine trend. Posture: {level} (mean rate {r}).",
    }
    return _trend_descriptions.get(trend, f"Posture level: {level} (mean rate {r}).")


def _compose_improvement_areas(
    posture: object,
    coverage_gaps: list[AttackCoverageGap],
    critical_target_count: int,
) -> tuple[str, ...]:
    areas: list[str] = []
    level = getattr(posture, "level", "unknown")
    if level in ("critical", "poor"):
        areas.append(
            "Reduce mean vulnerability rate through emergency remediation of critical findings."
        )
    if critical_target_count > 0:
        areas.append(f"Remediate {critical_target_count} target(s) at critical posture level.")
    under_covered = [g for g in coverage_gaps if g.coverage_rate < 0.50]
    if under_covered:
        areas.append(
            f"Expand attack coverage for {len(under_covered)} target(s) "
            f"with <50% category coverage."
        )
    total_missing = sum(len(g.missing_categories) for g in coverage_gaps)
    if total_missing > 0:
        areas.append(
            f"Schedule targeted campaigns for {total_missing} untested "
            f"attack categories across all targets."
        )
    if not areas:
        areas.append("Maintain current security posture through regular validation campaigns.")
    return tuple(areas)
