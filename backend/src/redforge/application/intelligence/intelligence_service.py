"""IntelligenceService — the canonical orchestrator for the reasoning pipeline.

Pipeline:
  IntelligenceContext
    → CoverageAnalyzer.analyze()       # per-target coverage gaps
    → GapAnalyzer.analyze()            # structural security gaps
    → InsightGenerator.generate()      # pattern/anomaly/trend insights
    → RecommendationGenerator.generate()  # rule-based recommendations
    → PriorityEngine.prioritize()      # score, deduplicate, sort
    → NarrativeBuilder.build_*()       # risk + posture narratives
    → IntelligenceReport.assemble()    # domain aggregate

No LLM. No I/O inside the service (repositories injected at call site).
All components are stateless and independently testable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.intelligence.coverage_analyzer import CoverageAnalyzer
from redforge.application.intelligence.gap_analyzer import GapAnalyzer
from redforge.application.intelligence.insight_generator import InsightGenerator
from redforge.application.intelligence.narrative_builder import NarrativeBuilder
from redforge.application.intelligence.priority_engine import PriorityEngine
from redforge.application.intelligence.recommendation_generator import (
    RecommendationGenerator,
)
from redforge.domain.intelligence.entity import IntelligenceReport

if TYPE_CHECKING:
    from redforge.application.intelligence.contracts import IntelligenceContext


class IntelligenceService:
    """Orchestrates the full intelligence reasoning pipeline.

    All collaborators are injected (default implementations provided for
    convenience — infrastructure can override by injecting custom implementations).

    Usage:
        service = IntelligenceService()
        report = service.generate_report(context)
    """

    def __init__(
        self,
        coverage_analyzer: CoverageAnalyzer | None = None,
        gap_analyzer: GapAnalyzer | None = None,
        insight_generator: InsightGenerator | None = None,
        recommendation_generator: RecommendationGenerator | None = None,
        priority_engine: PriorityEngine | None = None,
        narrative_builder: NarrativeBuilder | None = None,
    ) -> None:
        self._coverage = coverage_analyzer or CoverageAnalyzer()
        self._gaps = gap_analyzer or GapAnalyzer()
        self._insights = insight_generator or InsightGenerator()
        self._recommendations = recommendation_generator or RecommendationGenerator()
        self._priority = priority_engine or PriorityEngine()
        self._narratives = narrative_builder or NarrativeBuilder()

    def generate_report(self, context: IntelligenceContext) -> IntelligenceReport:
        """Run the full reasoning pipeline and return an IntelligenceReport."""
        # Phase 1: Coverage Analysis
        coverage_gaps = self._coverage.analyze(context)

        # Phase 2: Gap Analysis
        security_gaps = self._gaps.analyze(context, coverage_gaps)

        # Phase 3: Insight Generation
        insights = self._insights.generate(context)

        # Phase 4: Recommendation Generation
        raw_recommendations = self._recommendations.generate(
            context, insights, coverage_gaps, security_gaps
        )

        # Phase 5: Priority Engine (score, deduplicate, sort)
        recommendations = self._priority.prioritize(raw_recommendations, context)

        # Phase 6: Narrative Construction
        risk_narrative = self._narratives.build_risk_narrative(context, recommendations)
        posture_narrative = self._narratives.build_posture_narrative(context, coverage_gaps)

        # Phase 7: Assembly
        report, _events = IntelligenceReport.assemble(
            organization_id=context.organization_id,
            target_ids=context.target_ids,
            insights=tuple(insights),
            recommendations=tuple(recommendations),
            coverage_gaps=tuple(coverage_gaps),
            security_gaps=tuple(security_gaps),
            risk_narrative=risk_narrative,
            posture_narrative=posture_narrative,
            period_days=context.period_days,
        )
        return report
