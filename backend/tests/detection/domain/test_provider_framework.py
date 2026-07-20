"""Provider framework, taxonomy, and normalized model tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    ProviderNotRegistered,
    SchemaVersionMismatch,
)
from detection.domain.providers.normalized_models import (
    NormalizedCondition,
    NormalizedFieldSchema,
    NormalizedQuery,
    NormalizedTelemetryEvent,
    NormalizedTelemetryResult,
    QueryCostEstimate,
    SourceUnavailableResult,
)
from detection.domain.providers.registry import TelemetryProviderRegistry
from detection.domain.providers.taxonomy import (
    FIELD_REGISTRY,
    TELEMETRY_NAMESPACES,
)
from detection.domain.value_objects.enums import (
    ConditionOperator,
    FieldDataType,
    RuleLogicType,
    SourceHealthStatus,
    SourceType,
)
from detection.domain.value_objects.rule_logic import NormalizedFieldRef
from detection.domain.value_objects.telemetry import FieldDefinition, TimeWindow
from tests.detection.phase2_helpers import StubTelemetryAdapter, make_schema


def test_taxonomy_has_ten_namespaces() -> None:
    assert len(TELEMETRY_NAMESPACES) == 10
    for ns in (
        "event",
        "actor",
        "target",
        "action",
        "network",
        "process",
        "file",
        "cloud",
        "container",
        "identity",
    ):
        assert ns in TELEMETRY_NAMESPACES


def test_taxonomy_field_coverage() -> None:
    paths = FIELD_REGISTRY.all_paths()
    assert "event.event_type" in paths
    assert "process.command_line" in paths
    assert "cloud.api_call" in paths
    assert "identity.mfa_used" in paths
    assert len(paths) >= 40


@pytest.mark.parametrize(
    "path",
    [
        "event.event_id",
        "actor.ip_address",
        "target.asset_ref",
        "action.action_result",
        "network.src_ip",
        "process.hash",
        "file.path",
        "cloud.region",
        "container.pod_name",
        "identity.auth_method",
    ],
)
def test_validate_known_paths(path: str) -> None:
    ref = FIELD_REGISTRY.validate_path(path)
    assert ref.path == path


def test_validate_unknown_namespace() -> None:
    with pytest.raises(InvalidArgument):
        FIELD_REGISTRY.validate_path("vendor.custom_field")


def test_validate_unknown_field_in_namespace() -> None:
    with pytest.raises(InvalidArgument):
        FIELD_REGISTRY.validate_path("process.unknown_attr")


def test_fields_for_namespace() -> None:
    fields = FIELD_REGISTRY.fields_for_namespace("process")
    assert any(f.name == "command_line" for f in fields)


def test_registry_register_lookup_discover() -> None:
    registry = TelemetryProviderRegistry()
    adapter = StubTelemetryAdapter()
    registry.register(adapter)
    assert registry.has_provider(SourceType.CUSTOM_PUSH, "1.0.0")
    found = registry.lookup(SourceType.CUSTOM_PUSH, "1.0.0")
    assert found is adapter
    caps = registry.discover()
    assert len(caps) == 1
    assert caps[0].display_name == "Stub Custom Push"
    assert "query" in caps[0].capabilities


def test_registry_unregister() -> None:
    registry = TelemetryProviderRegistry()
    registry.register(StubTelemetryAdapter())
    registry.unregister(SourceType.CUSTOM_PUSH, "1.0.0")
    with pytest.raises(ProviderNotRegistered):
        registry.lookup(SourceType.CUSTOM_PUSH, "1.0.0")


def test_schema_version_mismatch() -> None:
    registry = TelemetryProviderRegistry()
    registry.register(StubTelemetryAdapter())
    with pytest.raises(SchemaVersionMismatch):
        registry.validate_schema_version(SourceType.CUSTOM_PUSH, "9.9.9")


def test_validate_health() -> None:
    registry = TelemetryProviderRegistry()
    registry.register(StubTelemetryAdapter(health=SourceHealthStatus.DEGRADED))
    assert (
        registry.validate_health(SourceType.CUSTOM_PUSH, "1.0.0")
        == SourceHealthStatus.DEGRADED
    )


def test_normalized_query_validation() -> None:
    now = datetime(2026, 7, 20, tzinfo=UTC)
    window = TimeWindow(start=now - timedelta(hours=1), end=now)
    with pytest.raises(InvalidArgument):
        NormalizedQuery(
            conditions=(),
            logic_type=RuleLogicType.CONDITION,
            window=window,
        )


def test_normalized_condition_exists() -> None:
    NormalizedCondition(
        field=NormalizedFieldRef("process.name"),
        operator=ConditionOperator.EXISTS,
        value=None,
    )
    with pytest.raises(InvalidArgument):
        NormalizedCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.EXISTS,
            value="x",
        )


def test_normalized_telemetry_event_rejects_vendor_keys() -> None:
    with pytest.raises(InvalidArgument):
        NormalizedTelemetryEvent(fields={"userIdentity.type": "AssumedRole"})


def test_normalized_telemetry_result_unavailable() -> None:
    result = NormalizedTelemetryResult.unavailable("down")
    assert result.source_unavailable is True
    assert result.events == ()


def test_source_unavailable_result() -> None:
    sur = SourceUnavailableResult(source_id="abc", reason="timeout", detail="5s")
    result = sur.to_telemetry_result()
    assert result.source_unavailable is True


def test_query_cost_estimate() -> None:
    est = QueryCostEstimate(estimated_events=10, estimated_duration_ms=5.0)
    assert est.expensive is False
    with pytest.raises(InvalidArgument):
        QueryCostEstimate(estimated_events=-1, estimated_duration_ms=0)


def test_adapter_execute_returns_normalized_only() -> None:
    events = [
        NormalizedTelemetryEvent(
            fields={"process.name": "cmd.exe", "event.event_type": "ProcessCreate"}
        )
    ]
    adapter = StubTelemetryAdapter(events=events)
    now = datetime(2026, 7, 20, tzinfo=UTC)
    window = TimeWindow(start=now - timedelta(hours=1), end=now)
    query = NormalizedQuery(
        conditions=(
            NormalizedCondition(
                field=NormalizedFieldRef("process.name"),
                operator=ConditionOperator.EQUALS,
                value="cmd.exe",
            ),
        ),
        logic_type=RuleLogicType.CONDITION,
        window=window,
    )
    result = adapter.execute_query(query, window)
    assert all("." in k for e in result.events for k in e.fields)


def test_normalized_field_schema() -> None:
    schema = make_schema()
    nfs = NormalizedFieldSchema(
        schema_version="1.0.0",
        fields={f.field_ref.path: f for f in schema.fields},
    )
    assert nfs.contains("process.name")
    assert not nfs.contains("vendor.field")


def test_field_definition_data_types() -> None:
    for dtype in FieldDataType:
        FieldDefinition(
            field_ref=NormalizedFieldRef("event.event_type"),
            data_type=dtype,
        )


def test_registry_clear() -> None:
    registry = TelemetryProviderRegistry()
    registry.register(StubTelemetryAdapter())
    registry.clear()
    assert registry.list_capabilities() == []
