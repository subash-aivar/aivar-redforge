"""Shared helpers for TelemetrySource Phase 2 tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from detection.domain.aggregates.telemetry_source import TelemetrySource
from detection.domain.providers.adapter import TelemetrySourceAdapter
from detection.domain.providers.normalized_models import (
    NormalizedFieldSchema,
    NormalizedQuery,
    NormalizedTelemetryEvent,
    NormalizedTelemetryResult,
    QueryCostEstimate,
)
from detection.domain.value_objects.enums import (
    FieldDataType,
    SourceHealthStatus,
    SourceTrustLevel,
    SourceType,
)
from detection.domain.value_objects.identifiers import TenantId
from detection.domain.value_objects.rule_logic import NormalizedFieldRef
from detection.domain.value_objects.telemetry import (
    ConnectionConfig,
    DataLatencyProfile,
    FieldDefinition,
    RetentionWindow,
    SourceSchema,
    TimeWindow,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 20, 14, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


def make_schema(
    *,
    version: str = "1.0.0",
    paths: list[str] | None = None,
) -> SourceSchema:
    default_paths = paths or [
        "event.event_type",
        "event.event_time",
        "process.name",
        "process.command_line",
        "actor.user_name",
    ]
    return SourceSchema(
        schema_version=version,
        fields=tuple(
            FieldDefinition(
                field_ref=NormalizedFieldRef(p),
                data_type=FieldDataType.STRING,
                required=p.startswith("event."),
            )
            for p in default_paths
        ),
    )


def make_connection(**kwargs: Any) -> ConnectionConfig:
    return ConnectionConfig(
        adapter_key=kwargs.get("adapter_key", "framework.stub"),
        tenant_scope_assertion=kwargs.get(
            "tenant_scope_assertion", "account_id=tenant-scope"
        ),
        endpoint_url=kwargs.get("endpoint_url"),
        options=kwargs.get("options", {}),
    )


def make_source(
    *,
    tenant_id: TenantId,
    now: datetime,
    name: str = "cloud-audit-primary",
    source_type: SourceType = SourceType.CUSTOM_PUSH,
    trust_level: SourceTrustLevel = SourceTrustLevel.SECONDARY,
    schema: SourceSchema | None = None,
    pop_events: bool = False,
) -> TelemetrySource:
    source = TelemetrySource.register(
        tenant_id=tenant_id,
        name=name,
        source_type=source_type,
        trust_level=trust_level,
        schema=schema or make_schema(),
        connection=make_connection(),
        latency_profile=DataLatencyProfile(
            expected_latency=timedelta(seconds=30),
            max_acceptable_latency=timedelta(minutes=5),
        ),
        retention=RetentionWindow(retention=timedelta(days=30)),
        now=now,
    )
    if pop_events:
        source.pop_events()
    return source


def make_window(now: datetime, hours: int = 1) -> TimeWindow:
    return TimeWindow(start=now - timedelta(hours=hours), end=now)


class StubTelemetryAdapter(TelemetrySourceAdapter):
    """Test-only adapter — not a vendor implementation."""

    source_type = SourceType.CUSTOM_PUSH
    schema_version = "1.0.0"
    display_name = "Stub Custom Push"
    capabilities = frozenset({"query", "simulate", "estimate"})

    def __init__(
        self,
        events: list[NormalizedTelemetryEvent] | None = None,
        *,
        health: SourceHealthStatus = SourceHealthStatus.HEALTHY,
        unavailable: bool = False,
    ) -> None:
        self._events = events or []
        self._health = health
        self._unavailable = unavailable
        self.queries: list[NormalizedQuery] = []

    def get_normalized_schema(self) -> NormalizedFieldSchema:
        schema = make_schema(version=self.schema_version)
        return NormalizedFieldSchema(
            schema_version=self.schema_version,
            fields={f.field_ref.path: f for f in schema.fields},
        )

    def execute_query(
        self,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> NormalizedTelemetryResult:
        self.queries.append(query)
        if self._unavailable:
            return NormalizedTelemetryResult.unavailable("stub unavailable")
        return NormalizedTelemetryResult(
            events=tuple(self._events[: query.limit]),
            query_duration_ms=1.5,
        )

    def validate_connectivity(self) -> SourceHealthStatus:
        return self._health

    def estimate_query_cost(
        self,
        query: NormalizedQuery,
        window: TimeWindow,
    ) -> QueryCostEstimate:
        return QueryCostEstimate(
            estimated_events=len(self._events),
            estimated_duration_ms=10.0,
            expensive=False,
        )
