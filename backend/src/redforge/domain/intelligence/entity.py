"""Core aggregate roots for the AI Security Intelligence bounded context.

SecurityInsight: a recognized pattern, anomaly, or trend detected from evidence.
Recommendation: an actionable security recommendation with evidence and remediation.
RecommendationBundle: a grouped, deduplicated, prioritized set of recommendations for one org.
RemediationPlan: the concrete step-by-step plan attached to one recommendation.
IntelligenceReport: the assembled report for one organization over a time window.

Domain layer — imports only domain.intelligence.*, shared.*, core.exceptions (ADR-0001).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.intelligence.events import (
    InsightDetected,
    IntelligenceDomainEvent,
    IntelligenceReportCreated,
    RecommendationGenerated,
)
from redforge.domain.intelligence.exceptions import RecommendationAlreadyTerminalError
from redforge.domain.intelligence.value_objects import (
    AttackCoverageGap,
    InsightType,
    PostureNarrative,
    RecommendationCategory,
    RecommendationEvidence,
    RecommendationPriority,
    RecommendationStatus,
    RemediationStep,
    RiskNarrative,
    SecurityGap,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

if TYPE_CHECKING:
    from datetime import datetime

_RECOMMENDATION_TERMINAL = frozenset({
    RecommendationStatus.IMPLEMENTED,
    RecommendationStatus.DISMISSED,
})


class SecurityInsight:
    """A recognized pattern or anomaly derived from security observations.

    Immutable after creation. Created by InsightGenerator domain service.
    insight_type: which class of pattern this is (PATTERN, ANOMALY, TREND, etc.)
    confidence: 0.0-1.0 (rules-based heuristic; not ML-derived)
    affected_targets: target IDs where the pattern was observed.
    supporting_evidence: what evidence types back this up.
    """

    __slots__ = (
        "_affected_targets",
        "_confidence",
        "_created_at",
        "_description",
        "_id",
        "_insight_type",
        "_organization_id",
        "_supporting_finding_ids",
        "_supporting_incident_ids",
        "_title",
    )

    def __init__(
        self,
        insight_id: str,
        organization_id: str,
        insight_type: InsightType,
        title: str,
        description: str,
        affected_targets: tuple[str, ...],
        supporting_finding_ids: tuple[str, ...],
        supporting_incident_ids: tuple[str, ...],
        confidence: float,
        created_at: datetime,
    ) -> None:
        self._id = insight_id
        self._organization_id = organization_id
        self._insight_type = insight_type
        self._title = title
        self._description = description
        self._affected_targets = affected_targets
        self._supporting_finding_ids = supporting_finding_ids
        self._supporting_incident_ids = supporting_incident_ids
        self._confidence = max(0.0, min(1.0, confidence))
        self._created_at = created_at

    @classmethod
    def create(
        cls,
        organization_id: str,
        insight_type: InsightType,
        title: str,
        description: str,
        affected_targets: tuple[str, ...],
        supporting_finding_ids: tuple[str, ...] = (),
        supporting_incident_ids: tuple[str, ...] = (),
        confidence: float = 0.7,
    ) -> tuple[SecurityInsight, list[IntelligenceDomainEvent]]:
        insight_id = str(EntityId.generate())
        now = utc_now()
        insight = cls(
            insight_id=insight_id,
            organization_id=organization_id,
            insight_type=insight_type,
            title=title,
            description=description,
            affected_targets=affected_targets,
            supporting_finding_ids=supporting_finding_ids,
            supporting_incident_ids=supporting_incident_ids,
            confidence=confidence,
            created_at=now,
        )
        event = InsightDetected(
            event_id=str(EntityId.generate()),
            insight_id=insight_id,
            organization_id=organization_id,
            insight_type=str(insight_type),
            title=title,
            affected_target_count=len(affected_targets),
        )
        return insight, [event]

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def insight_type(self) -> InsightType:
        return self._insight_type

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def affected_targets(self) -> tuple[str, ...]:
        return self._affected_targets

    @property
    def supporting_finding_ids(self) -> tuple[str, ...]:
        return self._supporting_finding_ids

    @property
    def supporting_incident_ids(self) -> tuple[str, ...]:
        return self._supporting_incident_ids

    @property
    def confidence(self) -> float:
        return self._confidence

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def is_high_confidence(self) -> bool:
        return self._confidence >= 0.8

    def __repr__(self) -> str:
        return (
            f"SecurityInsight(id={self._id!r}, type={self._insight_type!r}, "
            f"confidence={self._confidence:.2f})"
        )


class Recommendation:
    """An actionable security recommendation with priority, category, and remediation plan.

    Lifecycle: ACTIVE → ACKNOWLEDGED → IMPLEMENTED | DISMISSED

    rule_id: identifies which rule produced this recommendation (for deduplication).
    deduplication_key: (organization_id, target_id or "", category, rule_id).
    """

    __slots__ = (
        "_category",
        "_deduplication_key",
        "_description",
        "_evidence",
        "_id",
        "_organization_id",
        "_priority",
        "_priority_score",
        "_remediation_steps",
        "_rule_id",
        "_status",
        "_target_id",
        "_timestamps",
        "_title",
    )

    def __init__(
        self,
        recommendation_id: str,
        organization_id: str,
        target_id: str,
        category: RecommendationCategory,
        priority: RecommendationPriority,
        priority_score: float,
        title: str,
        description: str,
        evidence: RecommendationEvidence,
        remediation_steps: tuple[RemediationStep, ...],
        rule_id: str,
        status: RecommendationStatus,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = recommendation_id
        self._organization_id = organization_id
        self._target_id = target_id
        self._category = category
        self._priority = priority
        self._priority_score = priority_score
        self._title = title
        self._description = description
        self._evidence = evidence
        self._remediation_steps = remediation_steps
        self._rule_id = rule_id
        self._status = status
        self._timestamps = timestamps
        self._deduplication_key = f"{organization_id}:{target_id}:{category}:{rule_id}"

    @classmethod
    def create(
        cls,
        organization_id: str,
        target_id: str,
        category: RecommendationCategory,
        priority: RecommendationPriority,
        priority_score: float,
        title: str,
        description: str,
        evidence: RecommendationEvidence,
        remediation_steps: tuple[RemediationStep, ...],
        rule_id: str,
    ) -> tuple[Recommendation, list[IntelligenceDomainEvent]]:
        rec_id = str(EntityId.generate())
        now = utc_now()
        timestamps = AuditTimestamps(created_at=now, updated_at=now)
        rec = cls(
            recommendation_id=rec_id,
            organization_id=organization_id,
            target_id=target_id,
            category=category,
            priority=priority,
            priority_score=priority_score,
            title=title,
            description=description,
            evidence=evidence,
            remediation_steps=remediation_steps,
            rule_id=rule_id,
            status=RecommendationStatus.ACTIVE,
            timestamps=timestamps,
        )
        event = RecommendationGenerated(
            event_id=str(EntityId.generate()),
            recommendation_id=rec_id,
            organization_id=organization_id,
            target_id=target_id,
            category=str(category),
            priority=str(priority),
            rule_id=rule_id,
        )
        return rec, [event]

    def acknowledge(self) -> None:
        self._guard_not_terminal()
        self._status = RecommendationStatus.ACKNOWLEDGED
        self._timestamps = AuditTimestamps(
            created_at=self._timestamps.created_at,
            updated_at=utc_now(),
        )

    def mark_implemented(self) -> None:
        self._guard_not_terminal()
        self._status = RecommendationStatus.IMPLEMENTED
        self._timestamps = AuditTimestamps(
            created_at=self._timestamps.created_at,
            updated_at=utc_now(),
        )

    def dismiss(self) -> None:
        self._guard_not_terminal()
        self._status = RecommendationStatus.DISMISSED
        self._timestamps = AuditTimestamps(
            created_at=self._timestamps.created_at,
            updated_at=utc_now(),
        )

    def _guard_not_terminal(self) -> None:
        if self._status in _RECOMMENDATION_TERMINAL:
            raise RecommendationAlreadyTerminalError(self._id, str(self._status))

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def target_id(self) -> str:
        return self._target_id

    @property
    def category(self) -> RecommendationCategory:
        return self._category

    @property
    def priority(self) -> RecommendationPriority:
        return self._priority

    @property
    def priority_score(self) -> float:
        return self._priority_score

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def evidence(self) -> RecommendationEvidence:
        return self._evidence

    @property
    def remediation_steps(self) -> tuple[RemediationStep, ...]:
        return self._remediation_steps

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def status(self) -> RecommendationStatus:
        return self._status

    @property
    def deduplication_key(self) -> str:
        return self._deduplication_key

    @property
    def created_at(self) -> datetime:
        return self._timestamps.created_at

    @property
    def is_active(self) -> bool:
        return self._status == RecommendationStatus.ACTIVE

    def __repr__(self) -> str:
        return (
            f"Recommendation(id={self._id!r}, category={self._category!r}, "
            f"priority={self._priority!r}, score={self._priority_score:.1f})"
        )


class IntelligenceReport:
    """Assembled intelligence report for one organization over a time window.

    Aggregates: insights, recommendations, coverage gaps, security gaps,
    risk narrative, posture narrative.

    Immutable after creation. Produced by IntelligenceService.
    """

    __slots__ = (
        "_coverage_gaps",
        "_created_at",
        "_id",
        "_insights",
        "_organization_id",
        "_period_days",
        "_posture_narrative",
        "_recommendations",
        "_risk_narrative",
        "_security_gaps",
        "_target_ids",
    )

    def __init__(
        self,
        report_id: str,
        organization_id: str,
        target_ids: tuple[str, ...],
        insights: tuple[SecurityInsight, ...],
        recommendations: tuple[Recommendation, ...],
        coverage_gaps: tuple[AttackCoverageGap, ...],
        security_gaps: tuple[SecurityGap, ...],
        risk_narrative: RiskNarrative,
        posture_narrative: PostureNarrative,
        period_days: int,
        created_at: datetime,
    ) -> None:
        self._id = report_id
        self._organization_id = organization_id
        self._target_ids = target_ids
        self._insights = insights
        self._recommendations = recommendations
        self._coverage_gaps = coverage_gaps
        self._security_gaps = security_gaps
        self._risk_narrative = risk_narrative
        self._posture_narrative = posture_narrative
        self._period_days = period_days
        self._created_at = created_at

    @classmethod
    def assemble(
        cls,
        organization_id: str,
        target_ids: tuple[str, ...],
        insights: tuple[SecurityInsight, ...],
        recommendations: tuple[Recommendation, ...],
        coverage_gaps: tuple[AttackCoverageGap, ...],
        security_gaps: tuple[SecurityGap, ...],
        risk_narrative: RiskNarrative,
        posture_narrative: PostureNarrative,
        period_days: int,
    ) -> tuple[IntelligenceReport, list[IntelligenceDomainEvent]]:
        report_id = str(EntityId.generate())
        now = utc_now()
        report = cls(
            report_id=report_id,
            organization_id=organization_id,
            target_ids=target_ids,
            insights=insights,
            recommendations=recommendations,
            coverage_gaps=coverage_gaps,
            security_gaps=security_gaps,
            risk_narrative=risk_narrative,
            posture_narrative=posture_narrative,
            period_days=period_days,
            created_at=now,
        )
        critical_count = sum(
            1 for r in recommendations
            if r.priority == RecommendationPriority.CRITICAL
        )
        event = IntelligenceReportCreated(
            event_id=str(EntityId.generate()),
            report_id=report_id,
            organization_id=organization_id,
            recommendation_count=len(recommendations),
            insight_count=len(insights),
            critical_recommendation_count=critical_count,
        )
        return report, [event]

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def target_ids(self) -> tuple[str, ...]:
        return self._target_ids

    @property
    def insights(self) -> tuple[SecurityInsight, ...]:
        return self._insights

    @property
    def recommendations(self) -> tuple[Recommendation, ...]:
        return self._recommendations

    @property
    def coverage_gaps(self) -> tuple[AttackCoverageGap, ...]:
        return self._coverage_gaps

    @property
    def security_gaps(self) -> tuple[SecurityGap, ...]:
        return self._security_gaps

    @property
    def risk_narrative(self) -> RiskNarrative:
        return self._risk_narrative

    @property
    def posture_narrative(self) -> PostureNarrative:
        return self._posture_narrative

    @property
    def period_days(self) -> int:
        return self._period_days

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def critical_recommendation_count(self) -> int:
        return sum(
            1 for r in self._recommendations
            if r.priority == RecommendationPriority.CRITICAL
        )

    @property
    def has_critical_recommendations(self) -> bool:
        return self.critical_recommendation_count > 0

    def __repr__(self) -> str:
        return (
            f"IntelligenceReport(id={self._id!r}, org={self._organization_id!r}, "
            f"recs={len(self._recommendations)}, insights={len(self._insights)})"
        )
