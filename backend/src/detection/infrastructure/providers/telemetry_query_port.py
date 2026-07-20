"""TelemetryQueryPort — dispatches NormalizedQuery to TelemetryProviderRegistry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from detection.application.ports.i_telemetry_query_port import ITelemetryQueryPort
from detection.domain.exceptions.domain_exceptions import ProviderNotRegistered
from detection.domain.providers.normalized_models import (
    NormalizedTelemetryResult,
    QueryCostEstimate,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from detection.application.ports.i_unit_of_work import IUnitOfWork
    from detection.domain.providers.normalized_models import NormalizedQuery
    from detection.domain.providers.registry import TelemetryProviderRegistry
    from detection.domain.value_objects.identifiers import TelemetrySourceId, TenantId
    from detection.domain.value_objects.telemetry import TimeWindow


class RegistryTelemetryQueryPort(ITelemetryQueryPort):
    """
    Looks up TelemetrySource metadata, resolves adapter via registry, executes query.

    Never raises on adapter unavailability — returns NormalizedTelemetryResult.unavailable.
    """

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        registry: TelemetryProviderRegistry,
    ) -> None:
        self._uow_factory = uow_factory
        self._registry = registry

    async def execute_query(
        self,
        *,
        source_id: TelemetrySourceId,
        tenant_id: TenantId,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> NormalizedTelemetryResult:
        async with self._uow_factory() as uow:
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                return NormalizedTelemetryResult.unavailable(
                    f"source not found: {source_id}"
                )
            if not source.is_active:
                return NormalizedTelemetryResult.unavailable(
                    f"source deactivated: {source_id}"
                )
            try:
                adapter = self._registry.lookup(
                    source.source_type,
                    source.schema.schema_version,
                )
            except ProviderNotRegistered as exc:
                return NormalizedTelemetryResult.unavailable(str(exc))

            try:
                return adapter.execute_query(query, window)
            except Exception as exc:
                return NormalizedTelemetryResult.unavailable(
                    f"adapter error: {exc}"
                )

    async def estimate_cost(
        self,
        *,
        source_id: TelemetrySourceId,
        tenant_id: TenantId,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> QueryCostEstimate:
        async with self._uow_factory() as uow:
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                return QueryCostEstimate(
                    estimated_events=0,
                    estimated_duration_ms=0.0,
                    expensive=False,
                    notes="source not found",
                )
            try:
                adapter = self._registry.lookup(
                    source.source_type,
                    source.schema.schema_version,
                )
            except ProviderNotRegistered as exc:
                return QueryCostEstimate(
                    estimated_events=0,
                    estimated_duration_ms=0.0,
                    expensive=False,
                    notes=str(exc),
                )
            return adapter.estimate_query_cost(query, window)
