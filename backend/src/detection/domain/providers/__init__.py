"""Detection telemetry provider framework exports."""

from detection.domain.providers.adapter import TelemetrySourceAdapter
from detection.domain.providers.normalized_models import (
    NormalizedCondition,
    NormalizedFieldSchema,
    NormalizedQuery,
    NormalizedTelemetryEvent,
    NormalizedTelemetryResult,
    ProviderCapability,
    QueryCostEstimate,
    SourceUnavailableResult,
)
from detection.domain.providers.registry import TelemetryProviderRegistry
from detection.domain.providers.taxonomy import (
    FIELD_REGISTRY,
    TELEMETRY_NAMESPACES,
    NormalizedFieldRegistry,
)

__all__ = [
    "FIELD_REGISTRY",
    "TELEMETRY_NAMESPACES",
    "NormalizedCondition",
    "NormalizedFieldRegistry",
    "NormalizedFieldSchema",
    "NormalizedQuery",
    "NormalizedTelemetryEvent",
    "NormalizedTelemetryResult",
    "ProviderCapability",
    "QueryCostEstimate",
    "SourceUnavailableResult",
    "TelemetryProviderRegistry",
    "TelemetrySourceAdapter",
]
