from __future__ import annotations

from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome


class FeedbackIngestionService:
    def ingest(self, model: OptimizationModel, outcome: SuggestionOutcome) -> None:
        if outcome.delta is not None:
            model.record_feedback()
