"""ITelemetryQueryPort — outbound port for normalized telemetry queries."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.domain.providers.normalized_models import (
        NormalizedQuery,
        NormalizedTelemetryResult,
        QueryCostEstimate,
    )
    from detection.domain.value_objects.identifiers import TelemetrySourceId, TenantId
    from detection.domain.value_objects.telemetry import TimeWindow


class ITelemetryQueryPort(ABC):
    """
    Executes normalized queries against a registered TelemetrySource.

    Returns NormalizedTelemetryResult (no vendor types).
    On unavailability returns result with source_unavailable=True — does not raise.
    """

    @abstractmethod
    async def execute_query(
        self,
        *,
        source_id: TelemetrySourceId,
        tenant_id: TenantId,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> NormalizedTelemetryResult:
        """Dispatch query to the adapter for the registered source."""

    @abstractmethod
    async def estimate_cost(
        self,
        *,
        source_id: TelemetrySourceId,
        tenant_id: TenantId,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> QueryCostEstimate:
        """Estimate query cost via the registered adapter."""
