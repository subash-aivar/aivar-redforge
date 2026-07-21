"""ML anomaly score ACL — optional wiring to ml_pipeline (no domain imports)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from analytics.domain.ports.i_ml_anomaly_score_port import (
    IMLAnomalyScorePort,
    MLAnomalyScoreResult,
)

if TYPE_CHECKING:
    from uuid import UUID


class StubMLAnomalyScoreAdapter(IMLAnomalyScorePort):
    async def score(self, tenant_id: UUID, *, features: list[float]) -> MLAnomalyScoreResult:
        del tenant_id, features
        return MLAnomalyScoreResult(
            available=False, anomaly_score=0.0, is_anomaly=False, reason="AWAITING_MODEL"
        )


class CallableMLAnomalyScoreAdapter(IMLAnomalyScorePort):
    """Inject a callback for integration tests / composition root."""

    def __init__(
        self,
        fn: Callable[[UUID, list[float]], Awaitable[MLAnomalyScoreResult]],
    ) -> None:
        self._fn = fn

    async def score(self, tenant_id: UUID, *, features: list[float]) -> MLAnomalyScoreResult:
        return await self._fn(tenant_id, features)


class ThresholdMLAnomalyScoreAdapter(IMLAnomalyScorePort):
    """Deterministic stand-in for deployed Isolation Forest in unit tests."""

    def __init__(self, *, threshold: float = 5.0) -> None:
        self.threshold = threshold
        self.available = True

    async def score(self, tenant_id: UUID, *, features: list[float]) -> MLAnomalyScoreResult:
        del tenant_id
        if not self.available:
            return MLAnomalyScoreResult(False, 0.0, False, reason="AWAITING_MODEL")
        magnitude = sum(abs(f) for f in features) / max(len(features), 1)
        is_anom = magnitude >= self.threshold
        return MLAnomalyScoreResult(True, magnitude, is_anom, reason="ml_isolation_forest")
