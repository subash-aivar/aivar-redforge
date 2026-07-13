"""Priority scoring, ranking, and deduplication of Recommendations.

PriorityEngine is stateless. It takes a list of already-generated
Recommendations and applies contextual multipliers to produce a final
sorted ordering.

Multipliers applied (all multiplicative on top of base priority_score):
  - recency_factor: snapshots or findings in last 24h → x1.3
  - multi_target_factor: recommendation affects ≥3 targets → x1.2
  - posture_critical_factor: org is at CRITICAL posture level → x1.15
  - critical_finding_factor: has critical-severity findings → x1.25

Final priority label derived from the adjusted score:
  ≥ 85 → CRITICAL, ≥ 60 → HIGH, ≥ 35 → MEDIUM, else → LOW
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.domain.intelligence.entity import Recommendation
from redforge.domain.intelligence.value_objects import RecommendationPriority

if TYPE_CHECKING:
    from redforge.application.intelligence.contracts import IntelligenceContext


class PriorityEngine:
    """Stateless service: score and rank recommendations by contextual priority.

    Usage:
        engine = PriorityEngine()
        ranked = engine.prioritize(recommendations, context)
    """

    def prioritize(
        self,
        recommendations: list[Recommendation],
        context: IntelligenceContext,
    ) -> list[Recommendation]:
        """Return recommendations sorted by adjusted priority score descending."""
        if not recommendations:
            return []

        is_posture_critical = (
            context.posture is not None
            and context.posture.level == "critical"
        )
        has_recent_snapshot = _has_recent_snapshot(context)
        critical_finding_target_ids = {
            f.target_id for f in context.findings if f.severity == "critical"
        }

        scored: list[tuple[float, Recommendation]] = []
        for rec in recommendations:
            score = rec.priority_score
            score *= _recency_factor(rec, context, has_recent_snapshot)
            score *= _posture_factor(is_posture_critical)
            score *= _critical_finding_factor(rec, critical_finding_target_ids)
            score *= _multi_target_factor(rec, context)
            scored.append((score, rec))

        scored.sort(key=lambda t: t[0], reverse=True)

        # Return recommendations with updated priority labels (re-derive from score)
        result: list[Recommendation] = []
        for adjusted_score, rec in scored:
            new_priority = _label_from_score(adjusted_score)
            if new_priority != rec.priority:
                # Re-create with adjusted priority (create new via classmethod)
                updated, _ = Recommendation.create(
                    organization_id=rec.organization_id,
                    target_id=rec.target_id,
                    category=rec.category,
                    priority=new_priority,
                    priority_score=adjusted_score,
                    title=rec.title,
                    description=rec.description,
                    evidence=rec.evidence,
                    remediation_steps=rec.remediation_steps,
                    rule_id=rec.rule_id,
                )
                result.append(updated)
            else:
                result.append(rec)

        return result


def _label_from_score(score: float) -> RecommendationPriority:
    if score >= 85.0:
        return RecommendationPriority.CRITICAL
    if score >= 60.0:
        return RecommendationPriority.HIGH
    if score >= 35.0:
        return RecommendationPriority.MEDIUM
    return RecommendationPriority.LOW


def _has_recent_snapshot(context: IntelligenceContext) -> bool:
    """True if any snapshot was created in the last 24 hours."""
    import contextlib

    now = datetime.now(UTC)
    for snap in context.snapshots:
        if not snap.created_at_iso:
            continue
        with contextlib.suppress(Exception):
            dt = datetime.fromisoformat(snap.created_at_iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if (now - dt).total_seconds() < 86400:
                return True
    return False


def _recency_factor(
    rec: Recommendation,
    context: IntelligenceContext,
    has_recent_snapshot: bool,
) -> float:
    """Apply 1.3x multiplier if context has a snapshot in last 24h."""
    return 1.3 if has_recent_snapshot else 1.0


def _posture_factor(is_posture_critical: bool) -> float:
    """Apply 1.15x if org is at CRITICAL posture level."""
    return 1.15 if is_posture_critical else 1.0


def _critical_finding_factor(
    rec: Recommendation,
    critical_finding_target_ids: set[str],
) -> float:
    """Apply 1.25x if the recommendation's target has critical findings."""
    if rec.target_id and rec.target_id in critical_finding_target_ids:
        return 1.25
    return 1.0


def _multi_target_factor(
    rec: Recommendation,
    context: IntelligenceContext,
) -> float:
    """Apply 1.2x if the recommendation is org-level (targets all org targets)."""
    if not rec.target_id and len(context.target_ids) >= 3:
        return 1.2
    return 1.0
