from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseForecastEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class PostureForecastGenerated(BaseForecastEvent):
    forecast_id: str
    predicted_30d: float
    predicted_60d: float
    predicted_90d: float


@dataclass(frozen=True, slots=True, kw_only=True)
class ForecastAccuracyRecorded(BaseForecastEvent):
    forecast_id: str
    horizon_days: int
    absolute_error: float
