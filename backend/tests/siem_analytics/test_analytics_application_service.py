from __future__ import annotations

import dataclasses

import pytest

from siem_analytics.application.commands.analytics_queries import AnalyticsBatchQuery
from siem_analytics.application.dtos.analytics_outcome import AnalyticsStatus
from siem_analytics.application.exceptions import (
    ApplicationForbiddenError,
    EmptyBatchAnalyticsError,
)
from siem_analytics.application.registry.in_memory_analytics_provider_registry import (
    InMemoryAnalyticsProviderRegistry,
)
from siem_analytics.application.services.analytics_application_service import (
    AnalyticsApplicationService,
)
from siem_analytics.domain.value_objects.enums import AnalyticsAggregationType, AnalyticsEntityType
from siem_analytics.domain.value_objects.group_by_field import GroupByField
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import FakeAnalyticsProvider, fixed_result, make_metric, make_query


def _service(registry=None):
    return AnalyticsApplicationService(
        provider_registry=registry or InMemoryAnalyticsProviderRegistry()
    )


def _registry_with(entity_type, handler=None, metrics=()):
    registry = InMemoryAnalyticsProviderRegistry()
    registry.register(
        FakeAnalyticsProvider(entity_type, handler=handler or fixed_result(metrics=metrics))
    )
    return registry


# ---------------------------------------------------------------------------
# per-entity-type aggregation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entity_type",
    [
        AnalyticsEntityType.EVENTS,
        AnalyticsEntityType.ALERTS,
        AnalyticsEntityType.INVESTIGATIONS,
        AnalyticsEntityType.DETECTIONS,
        AnalyticsEntityType.CORRELATION_SESSIONS,
    ],
)
def test_aggregate_each_entity_type(entity_type):
    metric = make_metric(group_key={"entity_type": entity_type.value})
    registry = _registry_with(entity_type, metrics=(metric,))
    service = _service(registry)

    outcome = service.aggregate(make_query(entity_type=entity_type))

    assert outcome.status == AnalyticsStatus.SUCCEEDED
    assert outcome.result.metrics == (metric,)


def test_aggregate_without_role_raises_forbidden():
    service = _service()
    with pytest.raises(ApplicationForbiddenError):
        service.aggregate(make_query(actor_roles=()))


# ---------------------------------------------------------------------------
# time-range aggregation
# ---------------------------------------------------------------------------


def test_time_range_is_passed_through_to_provider():
    captured = {}

    def _handler(tenant_id, time_range, aggregation_type, group_by, filters):
        from siem_analytics.application.dtos.analytics_metric import AnalyticsResult

        captured["time_range"] = time_range
        return AnalyticsResult(entity_type="events", aggregation_type=aggregation_type.value)

    registry = _registry_with(AnalyticsEntityType.EVENTS, handler=_handler)
    service = _service(registry)
    query = make_query()

    service.aggregate(query)

    assert captured["time_range"] == query.time_range


# ---------------------------------------------------------------------------
# aggregation type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "aggregation_type",
    [
        AnalyticsAggregationType.COUNT,
        AnalyticsAggregationType.SUM,
        AnalyticsAggregationType.AVG,
        AnalyticsAggregationType.MIN,
        AnalyticsAggregationType.MAX,
    ],
)
def test_aggregation_type_is_passed_through_to_provider(aggregation_type):
    captured = {}

    def _handler(tenant_id, time_range, aggregation_type_arg, group_by, filters):
        from siem_analytics.application.dtos.analytics_metric import AnalyticsResult

        captured["aggregation_type"] = aggregation_type_arg
        return AnalyticsResult(entity_type="events", aggregation_type=aggregation_type_arg.value)

    registry = _registry_with(AnalyticsEntityType.EVENTS, handler=_handler)
    service = _service(registry)

    service.aggregate(make_query(aggregation_type=aggregation_type))

    assert captured["aggregation_type"] == aggregation_type


# ---------------------------------------------------------------------------
# grouping
# ---------------------------------------------------------------------------


def test_group_by_is_passed_through_to_provider():
    captured = {}

    def _handler(tenant_id, time_range, aggregation_type, group_by, filters):
        from siem_analytics.application.dtos.analytics_metric import AnalyticsResult

        captured["group_by"] = tuple(group_by)
        return AnalyticsResult(entity_type="events", aggregation_type=aggregation_type.value)

    registry = _registry_with(AnalyticsEntityType.EVENTS, handler=_handler)
    service = _service(registry)
    group_by = (GroupByField(field_name="severity"),)

    service.aggregate(make_query(group_by=group_by))

    assert captured["group_by"] == group_by


def test_duplicate_group_by_field_is_rejected():
    service = _service(_registry_with(AnalyticsEntityType.EVENTS))
    group_by = (GroupByField(field_name="severity"), GroupByField(field_name="severity"))
    outcome = service.aggregate(make_query(group_by=group_by))

    assert outcome.status == AnalyticsStatus.REJECTED
    assert outcome.failures[0].error_type == "InvalidGroupingError"


# ---------------------------------------------------------------------------
# filters
# ---------------------------------------------------------------------------


def test_invalid_filter_key_is_rejected():
    service = _service(_registry_with(AnalyticsEntityType.EVENTS))
    outcome = service.aggregate(make_query(filters={"": "x"}))

    assert outcome.status == AnalyticsStatus.REJECTED
    assert outcome.failures[0].error_type == "InvalidFilterError"


# ---------------------------------------------------------------------------
# unsupported provider / schema compatibility
# ---------------------------------------------------------------------------


def test_unsupported_provider():
    service = _service()  # empty registry
    outcome = service.aggregate(make_query())

    assert outcome.status == AnalyticsStatus.UNSUPPORTED_PROVIDER


def test_malformed_schema_version_is_rejected():
    service = _service(_registry_with(AnalyticsEntityType.EVENTS))
    outcome = service.aggregate(make_query(schema_version_raw="garbage"))

    assert outcome.status == AnalyticsStatus.REJECTED


def test_incompatible_schema_major_version_is_unsupported():
    registry = InMemoryAnalyticsProviderRegistry()
    registry.register(
        FakeAnalyticsProvider(AnalyticsEntityType.EVENTS, schema_version=SchemaVersion(2, 0))
    )
    service = _service(registry)

    outcome = service.aggregate(make_query(schema_version_raw="1.0"))

    assert outcome.status == AnalyticsStatus.UNSUPPORTED_PROVIDER


# ---------------------------------------------------------------------------
# provider exceptions
# ---------------------------------------------------------------------------


def test_provider_exception_produces_failed_outcome():
    def _explode(tenant_id, time_range, aggregation_type, group_by, filters):
        raise RuntimeError("backend unavailable")

    registry = _registry_with(AnalyticsEntityType.EVENTS, handler=_explode)
    service = _service(registry)

    outcome = service.aggregate(make_query())

    assert outcome.status == AnalyticsStatus.FAILED
    assert outcome.failures[0].error_type == "RuntimeError"


# ---------------------------------------------------------------------------
# batch analytics
# ---------------------------------------------------------------------------


def test_batch_aggregate_all_succeed():
    registry = _registry_with(AnalyticsEntityType.EVENTS, metrics=(make_metric(),))
    service = _service(registry)
    queries = tuple(make_query() for _ in range(3))

    result = service.aggregate_batch(
        AnalyticsBatchQuery(
            tenant_id=queries[0].tenant_id, queries=queries, actor_roles=("siem_analytics:viewer",)
        )
    )

    assert result.status == AnalyticsStatus.SUCCEEDED
    assert result.succeeded_count == 3


def test_batch_aggregate_partial_failure():
    registry = _registry_with(AnalyticsEntityType.EVENTS)
    service = _service(registry)
    queries = (
        make_query(entity_type=AnalyticsEntityType.EVENTS),
        make_query(entity_type=AnalyticsEntityType.ALERTS),  # unregistered
    )

    result = service.aggregate_batch(
        AnalyticsBatchQuery(
            tenant_id=queries[0].tenant_id, queries=queries, actor_roles=("siem_analytics:viewer",)
        )
    )

    assert result.status == AnalyticsStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1


def test_batch_aggregate_empty_raises():
    service = _service()
    with pytest.raises(EmptyBatchAnalyticsError):
        service.aggregate_batch(
            AnalyticsBatchQuery(
                tenant_id=make_query().tenant_id, queries=(), actor_roles=("siem_analytics:viewer",)
            )
        )


def test_batch_aggregate_without_role_raises_forbidden():
    service = _service()
    with pytest.raises(ApplicationForbiddenError):
        service.aggregate_batch(
            AnalyticsBatchQuery(
                tenant_id=make_query().tenant_id, queries=(make_query(),), actor_roles=()
            )
        )


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_analytics_outcome_is_frozen():
    registry = _registry_with(AnalyticsEntityType.EVENTS)
    service = _service(registry)
    outcome = service.aggregate(make_query())
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.status = AnalyticsStatus.REJECTED  # type: ignore[misc]
