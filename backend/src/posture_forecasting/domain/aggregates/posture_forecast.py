from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from posture_forecasting.domain.events.forecast_events import (
    ForecastAccuracyRecorded,
    PostureForecastGenerated,
)
from posture_forecasting.domain.exceptions.domain_exceptions import DomainInvariantViolation
from posture_forecasting.domain.value_objects.identifiers import ForecastId, TenantId
from posture_forecasting.domain.value_objects.snapshots import (
    ForecastAccuracyRecord,
    ForecastInputSnapshot,
)


class PostureForecast:
    __slots__ = (
        "_pending_events",
        "accuracy_records",
        "forecast_id",
        "generated_at",
        "input_snapshot",
        "model_id",
        "model_version",
        "predicted_30d",
        "predicted_60d",
        "predicted_90d",
        "tenant_id",
    )

    def __init__(
        self,
        forecast_id: ForecastId,
        tenant_id: TenantId,
        input_snapshot: ForecastInputSnapshot,
        predicted_30d: float,
        predicted_60d: float,
        predicted_90d: float,
        model_id: str,
        model_version: int,
        generated_at: datetime,
        *,
        accuracy_records: list[ForecastAccuracyRecord] | None = None,
    ) -> None:
        if input_snapshot is None:
            raise DomainInvariantViolation("input_snapshot required")
        if input_snapshot.tenant_id.value != tenant_id.value:
            raise DomainInvariantViolation("snapshot tenant mismatch")
        self.forecast_id = forecast_id
        self.tenant_id = tenant_id
        self.input_snapshot = input_snapshot
        self.predicted_30d = predicted_30d
        self.predicted_60d = predicted_60d
        self.predicted_90d = predicted_90d
        self.model_id = model_id
        self.model_version = model_version
        self.generated_at = generated_at
        self.accuracy_records = list(accuracy_records or [])
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        input_snapshot: ForecastInputSnapshot,
        predicted_30d: float,
        predicted_60d: float,
        predicted_90d: float,
        model_id: str,
        model_version: int,
    ) -> PostureForecast:
        now = datetime.now(UTC)
        forecast = cls(
            ForecastId.generate(),
            tenant_id,
            input_snapshot,
            predicted_30d,
            predicted_60d,
            predicted_90d,
            model_id,
            model_version,
            now,
        )
        forecast._pending_events.append(
            PostureForecastGenerated(
                tenant_id=str(tenant_id),
                aggregate_id=str(forecast.forecast_id),
                forecast_id=str(forecast.forecast_id),
                predicted_30d=predicted_30d,
                predicted_60d=predicted_60d,
                predicted_90d=predicted_90d,
            )
        )
        return forecast

    def record_accuracy(
        self, horizon_days: int, actual_score: float, predicted_score: float
    ) -> None:
        now = datetime.now(UTC)
        err = abs(actual_score - predicted_score)
        self.accuracy_records.append(
            ForecastAccuracyRecord(horizon_days, actual_score, predicted_score, err, now)
        )
        self._pending_events.append(
            ForecastAccuracyRecorded(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.forecast_id),
                forecast_id=str(self.forecast_id),
                horizon_days=horizon_days,
                absolute_error=err,
            )
        )
