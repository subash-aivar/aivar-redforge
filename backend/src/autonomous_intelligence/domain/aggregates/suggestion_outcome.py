"""SuggestionOutcome — append-only feedback aggregate (C5)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from autonomous_intelligence.domain.value_objects.enums import OutcomeType, SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


@dataclass
class SuggestionOutcome:
    outcome_id: UUID
    suggestion_id: UUID
    tenant_id: TenantId
    target_type: SuggestionTargetType
    outcome_type: OutcomeType
    measurement_window_days: int
    baseline_metric: float
    observed_metric: float | None
    delta: float | None
    measured_at: datetime | None

    @classmethod
    def create_pending(
        cls,
        suggestion_id: UUID,
        tenant_id: TenantId,
        target_type: SuggestionTargetType,
        measurement_window_days: int,
        baseline_metric: float,
    ) -> SuggestionOutcome:
        return cls(
            uuid4(),
            suggestion_id,
            tenant_id,
            target_type,
            OutcomeType.PENDING,
            measurement_window_days,
            baseline_metric,
            None,
            None,
            None,
        )

    def record_measurement(self, observed_metric: float, measured_at: datetime) -> None:
        self.observed_metric = observed_metric
        self.delta = observed_metric - self.baseline_metric
        self.measured_at = measured_at
        self.outcome_type = OutcomeType.MEASURABLE
