"""TelemetrySourceAdapter — Open/Closed provider contract (framework only)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from detection.domain.providers.normalized_models import (
        NormalizedFieldSchema,
        NormalizedQuery,
        NormalizedTelemetryResult,
        QueryCostEstimate,
    )
    from detection.domain.value_objects.enums import SourceHealthStatus, SourceType
    from detection.domain.value_objects.telemetry import TimeWindow


class TelemetrySourceAdapter(ABC):
    """
    Provider adapter contract.

    New telemetry integrations plug in by subclassing and registering with
    ``TelemetryProviderRegistry``. Core simulation/query orchestration never
    needs to change when a provider is added (Open/Closed Principle).

    Phase 2 ships the framework only — no vendor-specific adapters.
    """

    source_type: ClassVar[SourceType]
    schema_version: ClassVar[str]
    display_name: ClassVar[str] = ""
    capabilities: ClassVar[frozenset[str]] = frozenset()

    @abstractmethod
    def get_normalized_schema(self) -> NormalizedFieldSchema:
        """Return the normalized field schema this adapter produces."""

    @abstractmethod
    def execute_query(
        self,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> NormalizedTelemetryResult:
        """
        Execute a normalized query.

        Must never return vendor-specific field names in the result.
        On unavailability, prefer ``NormalizedTelemetryResult.unavailable``.
        """

    @abstractmethod
    def validate_connectivity(self) -> SourceHealthStatus:
        """Probe connectivity / health without executing a full query."""

    @abstractmethod
    def estimate_query_cost(
        self,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> QueryCostEstimate:
        """Estimate volume and duration for capacity planning."""
