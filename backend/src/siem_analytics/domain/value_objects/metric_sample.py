"""A single point-in-time metric observation (M42 Phase 11's read-model
building block). No new domain logic per M37 §11 — this is the closed,
validated shape metric aggregation is built on top of, not a new
computation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from siem_analytics.domain.exceptions.domain_exceptions import NegativeMetricValueError
from siem_analytics.domain.value_objects.enums import MetricCategory


@dataclass(frozen=True, slots=True)
class MetricSample:
    tenant_id: str
    category: MetricCategory
    value: float
    observed_at: datetime

    def __post_init__(self) -> None:
        if self.value < 0:
            raise NegativeMetricValueError(self.value)
